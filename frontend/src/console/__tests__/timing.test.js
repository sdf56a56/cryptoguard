import { test, expect } from "vitest";
import { formatMs } from "../timing.js";

test("two decimals exactly", () => {
  expect(formatMs(1.2345)).toBe("1.23");
  expect(formatMs(8)).toBe("8.00");
});

test("mock sleep label present", () => {
  expect(formatMs(66.666, true)).toBe("66.67 (Mock 模拟延迟)");
});
