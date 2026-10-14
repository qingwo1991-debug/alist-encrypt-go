import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Download runtime scope, not generated bindings or startup configuration.
// Add exceptions only with file + API + reason + expiry, never broad exclusions.
const scope = [
  'lib/utils/download_manager.dart',
  'lib/utils/download_file_owner.dart',
  'lib/utils/positional_file_writer.dart',
  'lib/utils/notification_manager.dart',
  'lib/pages/download_manager_page.dart',
];
const registeredExceptions = [];
const syncAPIs = /\b(?:exists|list|stat|create|delete|open|readAsBytes|readAsString|writeAsBytes|writeAsString|length|setPosition|writeFrom|flush|close|rename|copy|resolveSymbolicLinks|type|truncate)Sync\s*\(/g;
function calls(source) {
  // Remove comments/quoted strings while retaining executable Dart calls,
  // so docs mentioning statSync are not violations.
  const executable = source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g,
    match => match.replace(/[^\n]/g, ' '));
  return [...executable.matchAll(syncAPIs)].map(match => ({
    api: match[0].replace(/\s*\($/, ''),
    line: executable.slice(0, match.index).split('\n').length,
  }));
}
test('actual download/page/notification disk paths contain no sync calls', () => {
  const used = new Set();
  for (const file of scope) {
    const source = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
    for (const call of calls(source)) {
      const index = registeredExceptions.findIndex(exception =>
        exception.file === file && exception.api === call.api && exception.line === call.line &&
        exception.reason && exception.expiry);
      assert.notEqual(index, -1, `${file}:${call.line} reachable ${call.api} needs async IO or registered exception`);
      used.add(index);
    }
  }
  assert.equal(used.size, registeredExceptions.length, 'remove stale exceptions');
});
test('checker catches executable calls, not generated text or comments', () => {
  assert.deepEqual(calls("// f.statSync()\nfinal x = f.statSync();\nfinal s = 'listSync()';"),
    [{ api: 'statSync', line: 2 }]);
  assert.equal(calls('await f.stat();').length, 0);
});
test('all production entry points and cleanup share the file owner', () => {
  const manager = readFileSync(new URL('../lib/utils/download_manager.dart', import.meta.url), 'utf8');
  assert.equal((manager.match(/await _fileOwner\.reserve\(/g) || []).length, 2,
    'notification/background and page callback must both reserve');
  assert.equal((manager.match(/await _fileOwner\.release\(/g) || []).length, 2);
  assert.match(manager, /await _fileOwner\.clear\(/);
  assert.match(manager, /await _fileOwner\.delete\(/);
  const page = readFileSync(new URL('../lib/pages/download_manager_page.dart', import.meta.url), 'utf8');
  assert.match(page, /scanDownloadedFiles/);
  assert.match(page, /readDownloadedFile/);
  assert.match(page, /ListView\.builder/);
});
