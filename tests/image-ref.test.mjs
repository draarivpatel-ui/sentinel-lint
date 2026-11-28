import test from 'node:test';
import assert from 'node:assert/strict';
import { imageRepositoryMatchesPrefix, isValidImageRepositoryPrefix, parseImageReference } from '../src/image-ref.mjs';

test('parseImageReference accepts Docker repository component separators', () => {
  for (const reference of [
    'localhost:5000/team/run--time__base:nonroot',
    'registry.example.com:8443/ns/a--b__c.d:e',
  ]) {
    const parsed = parseImageReference(reference);
    assert.equal(parsed.valid, true, reference);
  }
});

test('parseImageReference still rejects invalid repository separators and uppercase repositories', () => {
  for (const reference of [
    'localhost:5000/team/run___time:nonroot',
    'localhost:5000/team/run--__time:nonroot',
    'localhost:5000/team/RUNTIME:nonroot',
  ]) {
    assert.equal(parseImageReference(reference).valid, false, reference);
  }
});

test('trusted image prefix validation accepts ports and Docker separators', () => {
  assert.equal(isValidImageRepositoryPrefix('localhost:5000/team/'), true);
  assert.equal(isValidImageRepositoryPrefix('registry.example.com:8443/te--am__x/'), true);
});

test('image prefix matching keeps exact slash boundaries', () => {
  assert.equal(imageRepositoryMatchesPrefix('localhost:5000/team/run--time', 'localhost:5000/team/'), true);
  assert.equal(imageRepositoryMatchesPrefix('localhost:5000/team-evil/run', 'localhost:5000/team/'), false);
  assert.equal(imageRepositoryMatchesPrefix('localhost:5000/team', 'localhost:5000/team'), true);
  assert.equal(imageRepositoryMatchesPrefix('localhost:5000/team-evil', 'localhost:5000/team'), false);
});
