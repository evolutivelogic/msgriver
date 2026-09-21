//! Runnable MsgRiver M2 service: local durable intake and fixed-egress ntfy.

#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use msgriver::StateOwnerLock;
use msgriver_client::{SubmitRequest, submit};
use msgriver_connectors::{
    driver::{Delivery, DeliveryOutcome, Driver},
    ntfy::NtfyEndpoint,
    whatsapp::{
        TemplateRegistration, WhatsappDriver, WhatsappEndpoint, WhatsappMessage, request_body,
    },
};
use msgriver_store::{
    M2Accepted, M2Submission, M3Submission, M4InboundSubmission, M6MessageStatus, M6QueueSummary,
    MigrationProvenance, Store, StoreOpenConfig,
};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_REQUEST: usize = 16 * 1024;
const MAX_WEBHOOK_CHALLENGE: usize = 1_024;
const SERVICE_POLL: Duration = Duration::from_millis(50);
const STORE_CONFIG: StoreOpenConfig = StoreOpenConfig::new(1_000, 16 * 1024 * 1024);

struct ServiceConfig {
    state_dir: PathBuf,
    socket: PathBuf,
    ntfy_url: String,
    ntfy_topic: String,
    whatsapp: Option<WhatsappConfig>,
    inbound: Option<InboundConfig>,
}

struct InboundConfig {
    listener: SocketAddr,
    app_secret: Vec<u8>,
    verify_token: Vec<u8>,
    policy: BTreeSet<(String, String)>,
    ntfy_topic: String,
    waba_id: String,
    phone_id: String,
}

struct WhatsappConfig {
    driver: Driver,
    template: String,
    locale: String,
    parameter_count: usize,
}

struct IncomingMessage {
    idempotency_key: String,
    body: String,
    title: Option<String>,
}

struct IncomingWhatsappMessage {
    idempotency_key: String,
    recipient: String,
    template: String,
    locale: String,
    parameters: Vec<String>,
}

enum IncomingRequest {
    Ntfy(IncomingMessage),
    Whatsapp(IncomingWhatsappMessage),
    InboundControl(bool),
    Status,
    MessageStatus(String),
    MessageRetry(String),
}

enum LocalRoute {
    Ntfy,
    Whatsapp,
    InboundEnable,
    InboundDisable,
    Status,
    MessageStatus(String),
    MessageRetry(String),
}

fn main() {
    let code = match run(env::args_os().skip(1).collect()) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("msgriver: {message}");
            1
        }
    };
    std::process::exit(code);
}

fn run(arguments: Vec<std::ffi::OsString>) -> Result<(), &'static str> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Err("expected `serve`, `send`, `inbound`, `status`, or `message`");
    };
    match command {
        "serve" => serve(parse_service_config(&arguments[1..])?),
        "send" => send(&arguments[1..]),
        "inbound" => inbound_control(&arguments[1..]),
        "status" => status(&arguments[1..]),
        "message" => message_control(&arguments[1..]),
        _ => Err("expected `serve`, `send`, `inbound`, `status`, or `message`"),
    }
}

fn serve(config: ServiceConfig) -> Result<(), &'static str> {
    msgriver::apply_linux_startup_policy().map_err(|_| "startup policy failed")?;
    msgriver::ensure_linux_non_root().map_err(|_| "refuses to run as root")?;
    prepare_state_root(&config.state_dir)?;
    let _owner_lock =
        StateOwnerLock::acquire(&config.state_dir).map_err(|_| "state is unavailable")?;
    let mut store = Store::open(&config.state_dir.join("msgriver.sqlite3"), STORE_CONFIG)
        .map_err(|_| "store open failed")?;
    store
        .apply_product_migrations(MigrationProvenance {
            binary_identity: b"msgriver-0.1.0-alpha",
            applied_at_unix_ms: now_unix_ms()?,
        })
        .map_err(|_| "store migration failed")?;
    store
        .m2_recover_interrupted(now_unix_ms()?)
        .map_err(|_| "store recovery failed")?;
    let ntfy_driver =
        Driver::Ntfy(NtfyEndpoint::parse(&config.ntfy_url).map_err(|_| "invalid ntfy endpoint")?);
    let listener = bind_socket(&config)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "socket setup failed")?;
    let inbound_listener = config
        .inbound
        .as_ref()
        .map(bind_inbound_listener)
        .transpose()?;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
                let _ = handle_request(&mut stream, &mut store, &config);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("socket accept failed"),
        }
        if let Some(inbound_listener) = inbound_listener.as_ref() {
            match inbound_listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
                    let _ = handle_inbound_request(&mut stream, &mut store, &config);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err("webhook accept failed"),
            }
        }
        dispatch_due(&mut store, &ntfy_driver, config.whatsapp.as_ref())?;
        thread::sleep(SERVICE_POLL);
    }
}

fn inbound_control(arguments: &[std::ffi::OsString]) -> Result<(), &'static str> {
    if arguments.len() != 3
        || !matches!(arguments[0].to_str(), Some("enable" | "disable"))
        || arguments[1] != "--socket"
    {
        return Err("invalid inbound control arguments");
    }
    let action = arguments[0]
        .to_str()
        .ok_or("invalid inbound control arguments")?;
    let socket = arguments[2]
        .to_str()
        .ok_or("invalid inbound control arguments")?;
    let (status, _) = local_post(socket, &format!("/v1/inbound/{action}"))
        .map_err(|_| "inbound control unavailable")?;
    (status == 200)
        .then_some(())
        .ok_or("inbound control refused")
}

fn status(arguments: &[std::ffi::OsString]) -> Result<(), &'static str> {
    if arguments.len() != 2 || arguments[0] != "--socket" {
        return Err("invalid status arguments");
    }
    let socket = arguments[1].to_str().ok_or("invalid status arguments")?;
    let (status, body) = local_post(socket, "/v1/status").map_err(|_| "status unavailable")?;
    if status != 200 {
        return Err("status refused");
    }
    println!("{body}");
    Ok(())
}

fn message_control(arguments: &[std::ffi::OsString]) -> Result<(), &'static str> {
    if arguments.len() != 5
        || !matches!(arguments[0].to_str(), Some("status" | "retry"))
        || arguments[1] != "--socket"
        || arguments[3] != "--message-id"
    {
        return Err("invalid message arguments");
    }
    let action = arguments[0].to_str().ok_or("invalid message arguments")?;
    let socket = arguments[2].to_str().ok_or("invalid message arguments")?;
    let message_id = arguments[4].to_str().ok_or("invalid message arguments")?;
    if !valid_message_id(message_id) {
        return Err("invalid message arguments");
    }
    let path = format!("/v1/messages/{message_id}/{action}");
    let (status, body) = local_post(socket, &path).map_err(|_| "message control unavailable")?;
    if (action == "status" && status == 200) || (action == "retry" && status == 202) {
        println!("{body}");
        return Ok(());
    }
    if action == "retry" && status == 409 {
        println!("{body}");
        return Err("message retry refused");
    }
    Err("message control refused")
}

fn local_post(socket: &str, path: &str) -> Result<(u16, String), &'static str> {
    let mut stream = UnixStream::connect(socket).map_err(|_| "local control unavailable")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(2))))
        .map_err(|_| "local control unavailable")?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| "local control unavailable")?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|_| "local control unavailable")?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("local control unavailable")?;
    let status = head
        .split("\r\n")
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("local control unavailable")?;
    Ok((status, body.to_owned()))
}

fn send(arguments: &[std::ffi::OsString]) -> Result<(), &'static str> {
    let socket = flag(arguments, "--socket")?;
    let key = flag(arguments, "--idempotency-key")?;
    let body = flag(arguments, "--body")?;
    let title = optional_flag(arguments, "--title")?;
    let response = submit(
        Path::new(socket),
        SubmitRequest {
            idempotency_key: key,
            body,
            title,
        },
    )
    .map_err(|_| "message was not accepted")?;
    println!(
        "{}{}",
        response.message_id,
        if response.deduplicated {
            " duplicate"
        } else {
            ""
        }
    );
    Ok(())
}

fn parse_service_config(arguments: &[std::ffi::OsString]) -> Result<ServiceConfig, &'static str> {
    validate_service_arguments(arguments)?;
    let state_dir = PathBuf::from(flag(arguments, "--state-dir")?);
    let socket = PathBuf::from(flag(arguments, "--socket")?);
    if socket.parent() != Some(state_dir.as_path()) {
        return Err("socket must be inside state directory");
    }
    let whatsapp = parse_whatsapp_config(arguments)?;
    let inbound = parse_inbound_config(arguments)?;
    Ok(ServiceConfig {
        state_dir,
        socket,
        ntfy_url: flag(arguments, "--ntfy-url")?.to_owned(),
        ntfy_topic: flag(arguments, "--ntfy-topic")?.to_owned(),
        whatsapp,
        inbound,
    })
}

fn validate_service_arguments(arguments: &[std::ffi::OsString]) -> Result<(), &'static str> {
    const FLAGS: [&str; 18] = [
        "--state-dir",
        "--socket",
        "--ntfy-url",
        "--ntfy-topic",
        "--whatsapp-url",
        "--whatsapp-phone-id",
        "--whatsapp-token-file",
        "--whatsapp-ca-file",
        "--whatsapp-template",
        "--whatsapp-locale",
        "--whatsapp-parameter-count",
        "--whatsapp-inbound-listen",
        "--whatsapp-inbound-app-secret-file",
        "--whatsapp-inbound-verify-token-file",
        "--whatsapp-inbound-policy-file",
        "--whatsapp-inbound-ntfy-topic",
        "--whatsapp-inbound-waba-id",
        "--whatsapp-inbound-phone-id",
    ];
    if !arguments.len().is_multiple_of(2) {
        return Err("invalid service arguments");
    }
    let mut seen = std::collections::BTreeSet::new();
    for pair in arguments.chunks_exact(2) {
        let name = pair[0].to_str().ok_or("invalid service arguments")?;
        if !FLAGS.contains(&name) || !seen.insert(name) {
            return Err("invalid service arguments");
        }
    }
    for required in ["--state-dir", "--socket", "--ntfy-url", "--ntfy-topic"] {
        if !seen.contains(required) {
            return Err("missing required argument");
        }
    }
    Ok(())
}

fn parse_inbound_config(
    arguments: &[std::ffi::OsString],
) -> Result<Option<InboundConfig>, &'static str> {
    let listen = optional_flag(arguments, "--whatsapp-inbound-listen")?;
    let app_secret = optional_flag(arguments, "--whatsapp-inbound-app-secret-file")?;
    let verify_token = optional_flag(arguments, "--whatsapp-inbound-verify-token-file")?;
    let policy_file = optional_flag(arguments, "--whatsapp-inbound-policy-file")?;
    let ntfy_topic = optional_flag(arguments, "--whatsapp-inbound-ntfy-topic")?;
    let waba_id = optional_flag(arguments, "--whatsapp-inbound-waba-id")?;
    let phone_id = optional_flag(arguments, "--whatsapp-inbound-phone-id")?;
    let Some((listen, app_secret, verify_token, policy_file, ntfy_topic, waba_id, phone_id)) =
        listen
            .zip(app_secret)
            .zip(verify_token)
            .zip(policy_file)
            .zip(ntfy_topic)
            .zip(waba_id)
            .zip(phone_id)
            .map(|((((((a, b), c), d), e), f), g)| (a, b, c, d, e, f, g))
    else {
        if [
            listen,
            app_secret,
            verify_token,
            policy_file,
            ntfy_topic,
            waba_id,
            phone_id,
        ]
        .iter()
        .any(Option::is_some)
        {
            return Err("incomplete WhatsApp inbound configuration");
        }
        return Ok(None);
    };
    let listener: SocketAddr = listen
        .parse()
        .map_err(|_| "invalid WhatsApp inbound configuration")?;
    if !listener.ip().is_loopback() {
        return Err("invalid WhatsApp inbound configuration");
    }
    let app_secret = read_owner_only_token(Path::new(app_secret))?.into_bytes();
    let verify_token = read_owner_only_token(Path::new(verify_token))?.into_bytes();
    let policy = parse_inbound_policy(&read_owner_only_file(Path::new(policy_file), 8 * 1024)?)?;
    if !valid_topic(ntfy_topic)
        || !valid_identifier(waba_id, 128)
        || !phone_id.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid WhatsApp inbound configuration");
    }
    Ok(Some(InboundConfig {
        listener,
        app_secret,
        verify_token,
        policy,
        ntfy_topic: ntfy_topic.to_owned(),
        waba_id: waba_id.to_owned(),
        phone_id: phone_id.to_owned(),
    }))
}

fn parse_inbound_policy(bytes: &[u8]) -> Result<BTreeSet<(String, String)>, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid WhatsApp inbound policy")?;
    let mut policy = BTreeSet::new();
    for line in text.lines() {
        let mut fields = line.split(' ');
        let (Some(sender), Some(verb), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err("invalid WhatsApp inbound policy");
        };
        if !(7..=20).contains(&sender.len())
            || !sender.bytes().all(|b| b.is_ascii_digit())
            || !matches!(verb, "notify" | "status")
            || !policy.insert((sender.to_owned(), verb.to_owned()))
        {
            return Err("invalid WhatsApp inbound policy");
        }
    }
    (!policy.is_empty())
        .then_some(policy)
        .ok_or("invalid WhatsApp inbound policy")
}

fn parse_whatsapp_config(
    arguments: &[std::ffi::OsString],
) -> Result<Option<WhatsappConfig>, &'static str> {
    let url = optional_flag(arguments, "--whatsapp-url")?;
    let phone_id = optional_flag(arguments, "--whatsapp-phone-id")?;
    let token_file = optional_flag(arguments, "--whatsapp-token-file")?;
    let ca_file = optional_flag(arguments, "--whatsapp-ca-file")?;
    let template = optional_flag(arguments, "--whatsapp-template")?;
    let locale = optional_flag(arguments, "--whatsapp-locale")?;
    let parameter_count = optional_flag(arguments, "--whatsapp-parameter-count")?;
    let Some((url, phone_id, token_file, template, locale, parameter_count)) = url
        .zip(phone_id)
        .zip(token_file)
        .zip(template)
        .zip(locale)
        .zip(parameter_count)
        .map(
            |(((((url, phone_id), token_file), template), locale), parameter_count)| {
                (url, phone_id, token_file, template, locale, parameter_count)
            },
        )
    else {
        if [
            url,
            phone_id,
            token_file,
            template,
            locale,
            parameter_count,
            ca_file,
        ]
        .iter()
        .any(Option::is_some)
        {
            return Err("incomplete WhatsApp configuration");
        }
        return Ok(None);
    };
    let parameter_count = parameter_count
        .parse::<usize>()
        .map_err(|_| "invalid WhatsApp configuration")?;
    let token = read_owner_only_token(Path::new(token_file))?;
    let additional_root = ca_file
        .map(|path| read_owner_only_file(Path::new(path), 32 * 1024))
        .transpose()?;
    let endpoint =
        WhatsappEndpoint::parse(url, phone_id).map_err(|_| "invalid WhatsApp configuration")?;
    let registration = TemplateRegistration {
        name: template,
        locale,
        parameter_count,
    };
    let driver = Driver::Whatsapp(
        WhatsappDriver::new_with_additional_root(endpoint, token, registration, additional_root)
            .map_err(|_| "invalid WhatsApp configuration")?,
    );
    Ok(Some(WhatsappConfig {
        driver,
        template: template.to_owned(),
        locale: locale.to_owned(),
        parameter_count,
    }))
}

fn flag<'a>(arguments: &'a [std::ffi::OsString], name: &str) -> Result<&'a str, &'static str> {
    let index = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or("missing required argument")?;
    arguments
        .get(index + 1)
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or("invalid argument")
}

fn optional_flag<'a>(
    arguments: &'a [std::ffi::OsString],
    name: &str,
) -> Result<Option<&'a str>, &'static str> {
    match arguments.iter().position(|argument| argument == name) {
        Some(index) => arguments
            .get(index + 1)
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .map(Some)
            .ok_or("invalid argument"),
        None => Ok(None),
    }
}

fn read_owner_only_token(path: &Path) -> Result<String, &'static str> {
    let bytes = read_owner_only_file(path, 4_097)?;
    let bytes = match bytes.strip_suffix(b"\n") {
        Some(with_newline) => with_newline.strip_suffix(b"\r").unwrap_or(with_newline),
        None => bytes.as_slice(),
    };
    let token = String::from_utf8(bytes.to_vec()).map_err(|_| "WhatsApp token file is unsafe")?;
    if token.is_empty() || token.len() > 4_096 || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("WhatsApp token file is unsafe");
    }
    Ok(token)
}

fn read_owner_only_file(path: &Path, maximum_size: i64) -> Result<Vec<u8>, &'static str> {
    use rustix::{
        fs::{AtFlags, CWD, Mode, OFlags, fstat, openat, statat},
        io::read,
    };

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "WhatsApp token file is unsafe")?;
    let before = statat(CWD, path.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "WhatsApp token file is unsafe")?;
    if !owner_only_file(&before, maximum_size) {
        return Err("WhatsApp token file is unsafe");
    }
    let file = openat(
        CWD,
        path.as_c_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "WhatsApp token file is unsafe")?;
    let after = fstat(&file).map_err(|_| "WhatsApp token file is unsafe")?;
    if !owner_only_file(&after, maximum_size)
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
    {
        return Err("WhatsApp token file is unsafe");
    }
    let size = usize::try_from(after.st_size).map_err(|_| "WhatsApp token file is unsafe")?;
    let mut bytes = vec![0_u8; size];
    let mut offset = 0;
    while offset < bytes.len() {
        let count =
            read(&file, &mut bytes[offset..]).map_err(|_| "WhatsApp token file is unsafe")?;
        if count == 0 {
            return Err("WhatsApp token file is unsafe");
        }
        offset += count;
    }
    let mut extra = [0_u8; 1];
    if read(&file, &mut extra).map_err(|_| "WhatsApp token file is unsafe")? != 0 {
        return Err("WhatsApp token file is unsafe");
    }
    Ok(bytes)
}

fn owner_only_file(metadata: &rustix::fs::Stat, maximum_size: i64) -> bool {
    rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile
        && metadata.st_mode & 0o7777 == 0o600
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_nlink == 1
        && metadata.st_size > 0
        && metadata.st_size <= maximum_size
}

fn prepare_state_root(root: &Path) -> Result<(), &'static str> {
    match fs::create_dir(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("state directory creation failed"),
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| "state directory inspection failed")?;
    if !metadata.file_type().is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err("state directory is unsafe");
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|_| "state directory permissions failed")
}

fn bind_socket(config: &ServiceConfig) -> Result<UnixListener, &'static str> {
    match fs::symlink_metadata(&config.socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(&config.socket).map_err(|_| "stale socket removal failed")?
        }
        Ok(_) => return Err("socket entry is unsafe"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("socket entry inspection failed"),
    }
    let listener = UnixListener::bind(&config.socket).map_err(|_| "socket bind failed")?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))
        .map_err(|_| "socket permissions failed")?;
    Ok(listener)
}

fn bind_inbound_listener(config: &InboundConfig) -> Result<TcpListener, &'static str> {
    let listener = TcpListener::bind(config.listener).map_err(|_| "webhook bind failed")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "webhook setup failed")?;
    Ok(listener)
}

fn handle_request(
    stream: &mut UnixStream,
    store: &mut Store,
    config: &ServiceConfig,
) -> Result<(), &'static str> {
    let request = read_request(stream)?;
    let accepted = match request {
        Some(IncomingRequest::Ntfy(IncomingMessage {
            idempotency_key,
            body,
            title,
        })) => store.m2_submit(
            M2Submission {
                idempotency_key: &idempotency_key,
                topic: &config.ntfy_topic,
                title: title.as_deref(),
                body: &body,
            },
            now_unix_ms()?,
        ),
        Some(IncomingRequest::Whatsapp(request)) => {
            let Some(whatsapp) = config.whatsapp.as_ref() else {
                write_response(stream, 404, "{\"error\":\"not found\"}")?;
                return Ok(());
            };
            let parameters: Vec<&str> = request.parameters.iter().map(String::as_str).collect();
            let registration = TemplateRegistration {
                name: &whatsapp.template,
                locale: &whatsapp.locale,
                parameter_count: whatsapp.parameter_count,
            };
            if request_body(
                registration,
                WhatsappMessage {
                    recipient: &request.recipient,
                    template: &request.template,
                    locale: &request.locale,
                    parameters: &parameters,
                },
            )
            .is_err()
            {
                write_response(stream, 400, "{\"error\":\"invalid request\"}")?;
                return Ok(());
            }
            let payload = canonical_whatsapp_payload(&request)?;
            store.m3_submit(
                M3Submission {
                    idempotency_key: &request.idempotency_key,
                    driver: "whatsapp",
                    destination: &request.recipient,
                    payload: &payload,
                },
                now_unix_ms()?,
            )
        }
        Some(IncomingRequest::InboundControl(enabled)) => {
            if config.inbound.is_none() {
                write_response(stream, 404, "{\"error\":\"not found\"}")?;
                return Ok(());
            }
            match store.m4_set_inbound_enabled(enabled) {
                Ok(()) => {
                    write_response(
                        stream,
                        200,
                        if enabled {
                            "{\"enabled\":true}"
                        } else {
                            "{\"enabled\":false}"
                        },
                    )?;
                    return Ok(());
                }
                Err(_) => {
                    write_response(stream, 409, "{\"error\":\"request refused\"}")?;
                    return Ok(());
                }
            }
        }
        Some(IncomingRequest::Status) => match store.m6_queue_summary() {
            Ok(summary) => {
                write_response(stream, 200, &json_queue_summary(summary))?;
                return Ok(());
            }
            Err(_) => {
                write_response(stream, 409, "{\"error\":\"request refused\"}")?;
                return Ok(());
            }
        },
        Some(IncomingRequest::MessageStatus(message_id)) => {
            match store.m6_message_status(&message_id) {
                Ok(Some(status)) => {
                    write_response(stream, 200, &json_message_status(&message_id, &status))?;
                    return Ok(());
                }
                Ok(None) => {
                    write_response(stream, 404, "{\"error\":\"not found\"}")?;
                    return Ok(());
                }
                Err(_) => {
                    write_response(stream, 409, "{\"error\":\"request refused\"}")?;
                    return Ok(());
                }
            }
        }
        Some(IncomingRequest::MessageRetry(message_id)) => {
            match store.m6_requeue_failed(&message_id, now_unix_ms()?) {
                Ok(Some(true)) => {
                    write_response(stream, 202, &json_retry(&message_id, true))?;
                    return Ok(());
                }
                Ok(Some(false)) => {
                    write_response(stream, 409, &json_retry(&message_id, false))?;
                    return Ok(());
                }
                Ok(None) => {
                    write_response(stream, 404, "{\"error\":\"not found\"}")?;
                    return Ok(());
                }
                Err(_) => {
                    write_response(stream, 409, "{\"error\":\"request refused\"}")?;
                    return Ok(());
                }
            }
        }
        None => {
            write_response(stream, 400, "{\"error\":\"invalid request\"}")?;
            return Ok(());
        }
    };
    match accepted {
        Ok(M2Accepted::New { message_id }) => {
            write_response(stream, 202, &json_result(&message_id, false))
        }
        Ok(M2Accepted::Existing { message_id }) => {
            write_response(stream, 200, &json_result(&message_id, true))
        }
        Err(_) => write_response(stream, 409, "{\"error\":\"request refused\"}"),
    }
}

fn read_request(stream: &mut UnixStream) -> Result<Option<IncomingRequest>, &'static str> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    while bytes.len() < MAX_REQUEST {
        let count = stream.read(&mut chunk).map_err(|_| "socket read failed")?;
        if count == 0 {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_REQUEST {
            return Ok(None);
        }
        if let Some(separator) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let Some(head) = std::str::from_utf8(&bytes[..separator]).ok() else {
                return Ok(None);
            };
            let Some((route, content_length)) = content_length(head) else {
                return Ok(None);
            };
            let maximum_body = MAX_REQUEST
                .checked_sub(separator + 4)
                .ok_or("request size failed")?;
            if content_length > maximum_body {
                return Ok(None);
            }
            while bytes.len() < separator + 4 + content_length {
                let count = stream.read(&mut chunk).map_err(|_| "socket read failed")?;
                if count == 0 {
                    return Ok(None);
                }
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() > MAX_REQUEST {
                    return Ok(None);
                }
            }
            if bytes.len() != separator + 4 + content_length {
                return Ok(None);
            }
            match route {
                LocalRoute::InboundEnable | LocalRoute::InboundDisable => {
                    return Ok(
                        (content_length == 0).then_some(IncomingRequest::InboundControl(matches!(
                            route,
                            LocalRoute::InboundEnable
                        ))),
                    );
                }
                LocalRoute::Status => {
                    return Ok((content_length == 0).then_some(IncomingRequest::Status));
                }
                LocalRoute::MessageStatus(message_id) => {
                    return Ok(
                        (content_length == 0).then_some(IncomingRequest::MessageStatus(message_id))
                    );
                }
                LocalRoute::MessageRetry(message_id) => {
                    return Ok(
                        (content_length == 0).then_some(IncomingRequest::MessageRetry(message_id))
                    );
                }
                LocalRoute::Ntfy | LocalRoute::Whatsapp => {}
            }
            let Some(value) =
                serde_json::from_slice::<serde_json::Value>(&bytes[separator + 4..]).ok()
            else {
                return Ok(None);
            };
            let Some(object) = value.as_object() else {
                return Ok(None);
            };
            return Ok(match route {
                LocalRoute::Ntfy => parse_ntfy_request(object).map(IncomingRequest::Ntfy),
                LocalRoute::Whatsapp => {
                    parse_whatsapp_request(object).map(IncomingRequest::Whatsapp)
                }
                LocalRoute::InboundEnable
                | LocalRoute::InboundDisable
                | LocalRoute::Status
                | LocalRoute::MessageStatus(_)
                | LocalRoute::MessageRetry(_) => None,
            });
        }
    }
    Ok(None)
}

fn handle_inbound_request(
    stream: &mut TcpStream,
    store: &mut Store,
    config: &ServiceConfig,
) -> Result<(), &'static str> {
    let Some(inbound) = config.inbound.as_ref() else {
        return Ok(());
    };
    let Some((head, body)) = read_http_request(stream)? else {
        return write_tcp_response(stream, 400, "");
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("webhook request failed")?;
    if request_line.starts_with("GET /v1/whatsapp/webhook?") {
        let query = request_line
            .strip_prefix("GET /v1/whatsapp/webhook?")
            .and_then(|value| value.strip_suffix(" HTTP/1.1"))
            .ok_or("webhook request failed")?;
        return handle_subscription(stream, query, inbound);
    }
    if request_line != "POST /v1/whatsapp/webhook HTTP/1.1" {
        return write_tcp_response(stream, 404, "");
    }
    let signature = header_once(&head, "x-hub-signature-256");
    let content_type = header_once(&head, "content-type");
    let Some(signature) = signature else {
        return write_tcp_response(stream, 401, "");
    };
    if content_type != Some("application/json")
        || !verify_signature(&inbound.app_secret, &body, signature)
    {
        return write_tcp_response(stream, 401, "");
    }
    let Some((sender, message_id, verb)) = parse_callback(&body, inbound) else {
        return write_tcp_response(stream, 200, "");
    };
    if !inbound.policy.contains(&(sender.clone(), verb.clone())) {
        return write_tcp_response(stream, 200, "");
    }
    let (driver, destination, payload) = if verb == "notify" {
        (
            "ntfy",
            inbound.ntfy_topic.clone(),
            "WhatsApp notify request accepted".to_owned(),
        )
    } else {
        let Some(whatsapp) = config.whatsapp.as_ref() else {
            return write_tcp_response(stream, 200, "");
        };
        let payload = canonical_whatsapp_payload(&IncomingWhatsappMessage {
            idempotency_key: "m4-status".to_owned(),
            recipient: sender.clone(),
            template: whatsapp.template.clone(),
            locale: whatsapp.locale.clone(),
            parameters: vec!["ready".to_owned()],
        })?;
        ("whatsapp", format!("+{sender}"), payload)
    };
    store
        .m4_submit_inbound(
            M4InboundSubmission {
                provider_message_id: &message_id,
                sender: &sender,
                verb: &verb,
                driver,
                destination: &destination,
                payload: &payload,
            },
            now_unix_ms()?,
        )
        .map_err(|_| "inbound store failed")?;
    write_tcp_response(stream, 200, "")
}

fn read_http_request(stream: &mut TcpStream) -> Result<Option<(String, Vec<u8>)>, &'static str> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    while bytes.len() <= MAX_REQUEST {
        let count = stream.read(&mut chunk).map_err(|_| "webhook read failed")?;
        if count == 0 {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(separator) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head =
                std::str::from_utf8(&bytes[..separator]).map_err(|_| "webhook request failed")?;
            if head.starts_with("GET /v1/whatsapp/webhook?") {
                return Ok(Some((head.to_owned(), Vec::new())));
            }
            let Some(length) =
                header_once(head, "content-length").and_then(|value| value.parse::<usize>().ok())
            else {
                return Ok(None);
            };
            if length > MAX_REQUEST - separator - 4 {
                return Ok(None);
            }
            while bytes.len() < separator + 4 + length {
                let count = stream.read(&mut chunk).map_err(|_| "webhook read failed")?;
                if count == 0 {
                    return Ok(None);
                }
                bytes.extend_from_slice(&chunk[..count]);
            }
            if bytes.len() != separator + 4 + length {
                return Ok(None);
            }
            let head = std::str::from_utf8(&bytes[..separator])
                .map_err(|_| "webhook request failed")?
                .to_owned();
            return Ok(Some((head, bytes[separator + 4..].to_vec())));
        }
    }
    Ok(None)
}

fn header_once<'a>(head: &'a str, wanted: &str) -> Option<&'a str> {
    let mut value = None;
    for line in head.split("\r\n").skip(1) {
        let (name, candidate) = line.split_once(':')?;
        if name.eq_ignore_ascii_case(wanted) && value.replace(candidate.trim()).is_some() {
            return None;
        }
    }
    value
}

fn verify_signature(secret: &[u8], body: &[u8], value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("sha256=") else {
        return false;
    };
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    let mut expected = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        expected[index] = match std::str::from_utf8(pair)
            .ok()
            .and_then(|v| u8::from_str_radix(v, 16).ok())
        {
            Some(value) => value,
            None => return false,
        };
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("nonempty HMAC key");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

fn handle_subscription(
    stream: &mut TcpStream,
    query: &str,
    config: &InboundConfig,
) -> Result<(), &'static str> {
    let mut mode = None;
    let mut token = None;
    let mut challenge = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return write_tcp_response(stream, 400, "");
        };
        match key {
            "hub.mode" if mode.replace(value).is_some() => {
                return write_tcp_response(stream, 400, "");
            }
            "hub.mode" => mode = Some(value),
            "hub.verify_token" if token.replace(value).is_some() => {
                return write_tcp_response(stream, 400, "");
            }
            "hub.verify_token" => token = Some(value),
            "hub.challenge" if challenge.replace(value).is_some() => {
                return write_tcp_response(stream, 400, "");
            }
            "hub.challenge" => challenge = Some(value),
            _ => return write_tcp_response(stream, 400, ""),
        }
    }
    let Some(challenge) = challenge.filter(|value| {
        !value.is_empty()
            && value.len() <= MAX_WEBHOOK_CHALLENGE
            && value.bytes().all(|byte| byte.is_ascii_graphic())
    }) else {
        return write_tcp_response(stream, 400, "");
    };
    if mode != Some("subscribe") {
        return write_tcp_response(stream, 400, "");
    }
    if token != std::str::from_utf8(&config.verify_token).ok() {
        return write_tcp_response(stream, 401, "");
    }
    write_tcp_response(stream, 200, challenge)
}

fn parse_callback(body: &[u8], config: &InboundConfig) -> Option<(String, String, String)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let entry = value.get("entry")?.as_array()?;
    if entry.len() != 1 || entry[0].get("id")?.as_str()? != config.waba_id {
        return None;
    }
    let changes = entry[0].get("changes")?.as_array()?;
    if changes.len() != 1 || changes[0].get("field")?.as_str()? != "messages" {
        return None;
    }
    let item = changes[0].get("value")?;
    if item.get("metadata")?.get("phone_number_id")?.as_str()? != config.phone_id {
        return None;
    }
    let messages = item.get("messages")?.as_array()?;
    if messages.len() != 1 {
        return None;
    }
    let message = &messages[0];
    let sender = message.get("from")?.as_str()?;
    let message_id = message.get("id")?.as_str()?;
    let verb = message.get("text")?.get("body")?.as_str()?;
    let timestamp = message.get("timestamp")?.as_str()?.parse::<i64>().ok()?;
    let now = now_unix_ms().ok()? / 1_000;
    if now.abs_diff(timestamp) > 600
        || !(7..=20).contains(&sender.len())
        || !sender.bytes().all(|byte| byte.is_ascii_digit())
        || !valid_identifier(message_id, 120)
        || !matches!(verb, "notify" | "status")
    {
        return None;
    }
    Some((sender.to_owned(), message_id.to_owned(), verb.to_owned()))
}

fn write_tcp_response(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), &'static str> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .and_then(|_| stream.flush())
    .map_err(|_| "webhook write failed")
}

fn valid_topic(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn parse_ntfy_request(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<IncomingMessage> {
    if object.len() != 3 || !object.contains_key("title") {
        return None;
    }
    let key = object.get("idempotency_key")?.as_str()?;
    let body = object.get("body")?.as_str()?;
    let title = match object.get("title")? {
        serde_json::Value::Null => None,
        value => Some(value.as_str()?.to_owned()),
    };
    Some(IncomingMessage {
        idempotency_key: key.to_owned(),
        body: body.to_owned(),
        title,
    })
}

fn parse_whatsapp_request(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<IncomingWhatsappMessage> {
    if object.len() != 5
        || !["idempotency_key", "to", "template", "locale", "params"]
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return None;
    }
    let parameters = object
        .get("params")?
        .as_array()?
        .iter()
        .map(serde_json::Value::as_str)
        .collect::<Option<Vec<_>>>()?;
    Some(IncomingWhatsappMessage {
        idempotency_key: object.get("idempotency_key")?.as_str()?.to_owned(),
        recipient: object.get("to")?.as_str()?.to_owned(),
        template: object.get("template")?.as_str()?.to_owned(),
        locale: object.get("locale")?.as_str()?.to_owned(),
        parameters: parameters.into_iter().map(str::to_owned).collect(),
    })
}

fn canonical_whatsapp_payload(request: &IncomingWhatsappMessage) -> Result<String, &'static str> {
    serde_json::to_string(&serde_json::json!({
        "template": request.template,
        "locale": request.locale,
        "params": request.parameters,
    }))
    .map_err(|_| "payload encoding failed")
}

fn content_length(head: &str) -> Option<(LocalRoute, usize)> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let route = match request_line {
        "POST /v1/messages HTTP/1.1" => LocalRoute::Ntfy,
        "POST /v1/whatsapp/messages HTTP/1.1" => LocalRoute::Whatsapp,
        "POST /v1/inbound/enable HTTP/1.1" => LocalRoute::InboundEnable,
        "POST /v1/inbound/disable HTTP/1.1" => LocalRoute::InboundDisable,
        "POST /v1/status HTTP/1.1" => LocalRoute::Status,
        _ => message_route(request_line)?,
    };
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return None;
            }
            length = value.trim().parse::<usize>().ok();
        }
    }
    length.map(|length| (route, length))
}

fn message_route(request_line: &str) -> Option<LocalRoute> {
    let path = request_line
        .strip_prefix("POST /v1/messages/")?
        .strip_suffix(" HTTP/1.1")?;
    let (message_id, action) = path.split_once('/')?;
    if !valid_message_id(message_id) || action.contains('/') {
        return None;
    }
    match action {
        "status" => Some(LocalRoute::MessageStatus(message_id.to_owned())),
        "retry" => Some(LocalRoute::MessageRetry(message_id.to_owned())),
        _ => None,
    }
}

fn dispatch_due(
    store: &mut Store,
    ntfy_driver: &Driver,
    whatsapp: Option<&WhatsappConfig>,
) -> Result<(), &'static str> {
    let Some(delivery) = store
        .m2_claim_due(now_unix_ms()?)
        .map_err(|_| "store claim failed")?
    else {
        return Ok(());
    };
    let outcome = match delivery.driver.as_str() {
        "ntfy" => ntfy_driver.deliver(Delivery::Ntfy {
            topic: &delivery.topic,
            title: delivery.title.as_deref(),
            body: &delivery.body,
        }),
        "whatsapp" => whatsapp_delivery(whatsapp, &delivery),
        _ => Err(msgriver_connectors::driver::DriverError::InvalidDelivery),
    };
    match outcome {
        Ok(DeliveryOutcome::Accepted { acknowledgement }) => {
            store.m2_mark_accepted(&delivery.message_id, &acknowledgement, now_unix_ms()?)
        }
        Ok(DeliveryOutcome::RateLimited | DeliveryOutcome::Transient) => store.m2_mark_retry(
            &delivery.message_id,
            "ntfy temporary failure",
            1_000,
            now_unix_ms()?,
        ),
        Ok(DeliveryOutcome::Ambiguous) => store.m2_mark_ambiguous(
            &delivery.message_id,
            "ntfy response uncertain",
            now_unix_ms()?,
        ),
        Ok(DeliveryOutcome::Permanent | DeliveryOutcome::AuthOrConfig) => store.m2_mark_failed(
            &delivery.message_id,
            "ntfy rejected request",
            now_unix_ms()?,
        ),
        Err(_) => {
            store.m2_mark_failed(&delivery.message_id, "ntfy request invalid", now_unix_ms()?)
        }
    }
    .map_err(|_| "store outcome failed")
}

fn whatsapp_delivery(
    whatsapp: Option<&WhatsappConfig>,
    delivery: &msgriver_store::M2Delivery,
) -> Result<DeliveryOutcome, msgriver_connectors::driver::DriverError> {
    let Some(whatsapp) = whatsapp else {
        return Err(msgriver_connectors::driver::DriverError::InvalidDelivery);
    };
    let Some(payload) = parse_canonical_whatsapp_payload(&delivery.payload) else {
        return Err(msgriver_connectors::driver::DriverError::InvalidDelivery);
    };
    let parameters: Vec<&str> = payload.parameters.iter().map(String::as_str).collect();
    whatsapp.driver.deliver(Delivery::Whatsapp {
        recipient: &delivery.destination,
        template: &payload.template,
        locale: &payload.locale,
        parameters: &parameters,
    })
}

struct CanonicalWhatsappPayload {
    template: String,
    locale: String,
    parameters: Vec<String>,
}

fn parse_canonical_whatsapp_payload(payload: &str) -> Option<CanonicalWhatsappPayload> {
    let value = serde_json::from_str::<serde_json::Value>(payload).ok()?;
    let object = value.as_object()?;
    if object.len() != 3
        || !["template", "locale", "params"]
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return None;
    }
    let parameters = object
        .get("params")?
        .as_array()?
        .iter()
        .map(serde_json::Value::as_str)
        .collect::<Option<Vec<_>>>()?;
    let canonical = CanonicalWhatsappPayload {
        template: object.get("template")?.as_str()?.to_owned(),
        locale: object.get("locale")?.as_str()?.to_owned(),
        parameters: parameters.into_iter().map(str::to_owned).collect(),
    };
    let reconstructed = serde_json::to_string(&serde_json::json!({
        "template": canonical.template,
        "locale": canonical.locale,
        "params": canonical.parameters,
    }))
    .ok()?;
    (reconstructed == payload).then_some(canonical)
}

fn write_response(stream: &mut UnixStream, status: u16, body: &str) -> Result<(), &'static str> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| "socket write failed")
}

fn json_result(message_id: &str, deduplicated: bool) -> String {
    format!("{{\"message_id\":\"{message_id}\",\"deduplicated\":{deduplicated}}}")
}

fn json_queue_summary(summary: M6QueueSummary) -> String {
    format!(
        "{{\"counts\":{{\"queued\":{},\"retry_scheduled\":{},\"sending\":{},\"provider_accepted\":{},\"failed\":{},\"ambiguous\":{}}}}}",
        summary.queued,
        summary.retry_scheduled,
        summary.sending,
        summary.provider_accepted,
        summary.failed,
        summary.ambiguous,
    )
}

fn json_message_status(message_id: &str, status: &M6MessageStatus) -> String {
    let recovery = match status.state.as_str() {
        "failed" => "retry_after_configuration_check",
        "ambiguous" => "manual_resolution_required",
        _ => "none",
    };
    format!(
        "{{\"message_id\":\"{message_id}\",\"state\":\"{}\",\"attempts\":{},\"recovery\":\"{recovery}\"}}",
        status.state, status.attempts
    )
}

fn json_retry(message_id: &str, requeued: bool) -> String {
    format!("{{\"message_id\":\"{message_id}\",\"requeued\":{requeued}}}")
}

fn valid_message_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn now_unix_ms() -> Result<i64, &'static str> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock failed")?;
    i64::try_from(duration.as_millis()).map_err(|_| "clock failed")
}
