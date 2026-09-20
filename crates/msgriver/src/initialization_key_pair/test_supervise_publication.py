#!/usr/bin/python3
"""Executable, hermetic controls for the adjudicated Task 0008 parser fix."""
import unittest

from supervise_publication import NAMES, audit, exact_write_limit


BASE = '/tmp/msgriver-publication-red-parser'
ROOT = BASE + '/state'
ANCHORED = BASE + '/state.anchored'
SIGNALS = BASE + '/signals-1'


def marker(name):
    return f'openat(AT_FDCWD, "{SIGNALS}/{name}", O_WRONLY|O_CREAT, 0600) = 9'


def trace(line, discovered):
    lines = [marker('scope-begin')]
    if discovered:
        lines += [marker('boundary-OpenRoot-Before'),
                  f'openat(AT_FDCWD, "{ROOT}", O_RDONLY|O_DIRECTORY|O_NOFOLLOW) = 3<{ROOT}>',
                  marker('boundary-OpenRoot-After')]
    return lines + [line, marker('scope-end')]


def metadata(syscall, descriptor, path='""', flags='AT_EMPTY_PATH'):
    if syscall == 'statx':
        return f'statx({descriptor}, {path}, {flags}, STATX_ALL, {{stx_mode=S_IFREG|0600, stx_size=0}}) = 0'
    return f'newfstatat({descriptor}, {path}, {{st_mode=S_IFREG|0600, st_mtim={{tv_sec=0, tv_nsec=0}}}}, {flags}) = 0'


class MetadataParserControls(unittest.TestCase):
    def test_zero_write_format(self):
        self.assertTrue(exact_write_limit('write(0x7, 0x1000, 0) = 0', 7, 0))
        self.assertTrue(exact_write_limit('write(0x7, 0x1000, 0x0) = 0x0', 7, 0))
        for line in (
            'write(0x7, 0x1000, 0) = 1',
            'write(0x7, 0x1000, 1) = 0',
            'write(0x8, 0x1000, 0) = 0',
            'write(0x7, 0x1000, 0x00) = 0x00',
        ):
            with self.subTest(line=line):
                self.assertFalse(exact_write_limit(line, 7, 0))
        self.assertTrue(exact_write_limit('write(0x7, 0x1000, 0x1) = 0x1', 7, 1))
        self.assertFalse(exact_write_limit('write(0x7, 0x1000, 1) = 1', 7, 1))

    def test_positive_metadata(self):
        for syscall in ('statx', 'newfstatat'):
            for root in (ROOT, ANCHORED):
                for flags in ('AT_EMPTY_PATH', 'AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH',
                              'AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW'):
                    for discovered, descriptor in ((False, f'4<{root}/msgriver.lock>'),
                                                   (True, f'4<{root}/msgriver.lock>'),
                                                   (True, f'3<{root}>')):
                        with self.subTest(syscall=syscall, root=root, flags=flags,
                                          discovered=discovered, descriptor=descriptor):
                            audit(trace(metadata(syscall, descriptor, flags=flags), discovered), 'parser')

    def test_negative_metadata(self):
        for syscall in ('statx', 'newfstatat'):
            valid = metadata(syscall, f'3<{ROOT}>')
            cases = [
                ('undiscovered root', valid, False),
                ('wrong root fd', metadata(syscall, f'4<{ROOT}>'), True),
                ('unannotated fd', metadata(syscall, '3'), True),
                ('symbolic fd', metadata(syscall, f'AT_FDCWD<{ROOT}>'), True),
                ('negative fd', metadata(syscall, f'-3<{ROOT}>'), True),
                ('hex fd', metadata(syscall, f'0x3<{ROOT}>'), True),
                ('partial annotation', metadata(syscall, f'3<{ROOT}'), True),
                ('trailing annotation', metadata(syscall, f'3<{ROOT}>junk'), True),
                ('extra argument', valid.replace(', "",', ', "", 0,'), True),
                ('missing argument', valid.replace(', STATX_ALL', '') if syscall == 'statx'
                 else valid.replace(', AT_EMPTY_PATH)', ')'), True),
                ('other syscall', valid.replace(syscall, 'openat', 1), True),
                ('prefixed syscall', 'other_' + valid, True),
                ('later empty', valid.replace('= 0', ', "") = 0'), True),
                ('later allowed quote', valid.replace('= 0', f', "{ROOT}") = 0'), True),
                ('unbalanced metadata', valid.replace('}', '', 1), True),
                ('wrong flags position',
                 f'statx(3<{ROOT}>, "", 0, AT_EMPTY_PATH, {{}}) = 0' if syscall == 'statx'
                 else f'newfstatat(3<{ROOT}>, "", AT_EMPTY_PATH, 0) = 0', True),
                ('flag in metadata', valid.replace('AT_EMPTY_PATH', '0').replace(
                    'S_IFREG', 'AT_EMPTY_PATH'), True),
                ('empty other argument',
                 f'{syscall}(3<{ROOT}>, "{ROOT}", "", AT_EMPTY_PATH) = 0', True),
            ]
            for flags in ('0', 'AT_SYMLINK_NOFOLLOW', 'NOT_AT_EMPTY_PATH',
                          'AT_EMPTY_PATH_EXTRA', '"AT_EMPTY_PATH"', '0x1000',
                          'AT_EMPTY_PATH||0', 'AT_EMPTY_PATH+0'):
                cases.append(('invalid flag ' + flags, metadata(syscall, f'3<{ROOT}>', flags=flags), True))
            for path in (ROOT + '/', ROOT + '/.', ROOT + '/child/..', ROOT + '-other',
                         ROOT + ' (deleted)', BASE + '/other',
                         ROOT + '/msgriver.lock.extra', ROOT + '//msgriver.lock',
                         ROOT + '/./msgriver.lock', ROOT + '/msgriver.lock (deleted)',
                         ANCHORED + '/msgriver.lock/..', *[ROOT + '/' + name for name in NAMES],
                         *[ANCHORED + '/' + name for name in NAMES]):
                for discovered in (False, True):
                    cases.append(('disallowed annotation ' + path,
                                  metadata(syscall, f'3<{path}>'), discovered))
            for name, line, discovered in cases:
                with self.subTest(syscall=syscall, name=name, discovered=discovered):
                    with self.assertRaisesRegex(AssertionError, 'unexpected path effect'):
                        audit(trace(line, discovered), 'parser')

    def test_existing_path_and_effect_rejections(self):
        lines = [
            f'openat(3<{ROOT}>, "", O_RDONLY|AT_EMPTY_PATH) = -1 EINVAL',
            f'renameat2(3<{ROOT}>, "", 3<{ROOT}>, "", AT_EMPTY_PATH) = -1 EINVAL',
            f'statx(3<{ROOT}>, "unrelated", AT_EMPTY_PATH, STATX_ALL, {{}}) = 0',
            'socket(AF_INET, SOCK_STREAM, 0) = 4',
            'write(0x1, 0x1000, 0x20) = 0x20',
            'getrandom(0x1000, 0x20, 0) = 0x20',
        ]
        for name in NAMES:
            lines += [metadata('statx', f'3<{ROOT}>', path=f'"{ROOT}/{name}"'),
                      metadata('newfstatat', f'3<{ROOT}>', path=f'"{ANCHORED}/{name}"'),
                      f'openat(4<{ROOT}>, "{name}", O_RDONLY) = 5']
        for line in lines:
            with self.subTest(line=line):
                with self.assertRaises(AssertionError):
                    audit(trace(line, True), 'parser')
        for name in NAMES:
            with self.subTest(preflight=name):
                lines = trace(marker('boundary-Preflight(0)-Before'), True)
                lines.insert(-1, f'openat(3<{ROOT}>, "{name}", O_RDONLY) = 5')
                with self.assertRaisesRegex(AssertionError, 'preflight opened an existing entry'):
                    audit(lines, 'parser')


if __name__ == '__main__':
    unittest.main()
