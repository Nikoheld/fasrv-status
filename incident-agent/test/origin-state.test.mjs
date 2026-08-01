import test from "node:test";
import assert from "node:assert/strict";
import { originRestarted } from "../lib/origin-state.mjs";

test("detects restart counters and changed component generations", () => {
  const previous = { restartCount: 2, generation: "start-a" };
  assert.equal(originRestarted({ restartCount: 3, generation: "start-a" }, previous), true);
  assert.equal(originRestarted({ restartCount: 2, generation: "start-b" }, previous), true);
  assert.equal(originRestarted({ restartCount: 2, generation: "start-a" }, previous), false);
  assert.equal(originRestarted({ restartCount: 0, generation: "start-a" }, null), false);
});
