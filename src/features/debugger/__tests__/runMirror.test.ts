import { beforeEach, expect, it, vi } from "vitest";
import type { LaunchConfig } from "@/platform/ipc";
import {
  provideNotificationService,
  provideToolWindowService,
  type ToolWindowService,
} from "@/workbench/contributions";
import { handleDebugEvent, startSession, useDebug } from "../state";

const ipc = vi.hoisted(() => ({ debugStart: vi.fn() }));

/** Lines the run printed before the attach, and the listener the mirror registered. */
const run = vi.hoisted(() => ({
  lines: [] as Array<{ text: string; kind: string }>,
  listener: null as null | ((text: string, kind: string) => void),
  stopped: 0,
}));

vi.mock("@/platform/ipc", async (original) => {
  const real = await original<typeof import("@/platform/ipc")>();
  return { ...real, isTauri: () => true, commands: { ...real.commands, ...ipc } };
});

vi.mock("@/features/run/store", () => ({
  runLines: () => run.lines,
  onRunLines: (_session: unknown, onLine: (text: string, kind: string) => void) => {
    run.listener = onLine;
    return () => {
      run.stopped++;
    };
  },
}));

const attach: LaunchConfig = {
  name: "YonBIP: Run",
  adapter: "java-debug",
  request: "attach",
  program: null,
  args: [],
  cwd: "/p",
  env: {},
  extraJson: JSON.stringify({ hostName: "127.0.0.1", port: 35549 }),
};

const consoleText = (id: number) => (useDebug.getState().console[id] ?? []).map((line) => line.text).join("\n");

beforeEach(() => {
  run.lines = [];
  run.listener = null;
  run.stopped = 0;
  useDebug.setState({ sessions: {}, active: null, console: {} });
  provideNotificationService({ notify: vi.fn() });
  provideToolWindowService({ show: vi.fn() } as unknown as ToolWindowService);
  vi.clearAllMocks();
  // The adapter's session announces itself, then `debug.start` resolves with its id.
  ipc.debugStart.mockImplementation(async () => {
    handleDebugEvent(42, { kind: "started", name: "YonBIP: Run", adapter: "java-debug", parent: null });
    return { status: "ok", data: 42 };
  });
});

it("shows the output of the process it attached to", async () => {
  run.lines = [
    { text: "java -agentlib:jdwp=… th.demo.JavacProbe", kind: "stdout" },
    { text: "workspace class: nccloud.openapi.utils.Const", kind: "stdout" },
    { text: "a warning", kind: "system" },
  ];
  expect(await startSession(attach, { process: 7, runConfig: null as never })).toBe(42);

  expect(consoleText(42)).toContain("workspace class: nccloud.openapi.utils.Const");
  // System lines belong to the run's own console; they are not debuggee output.
  expect(consoleText(42)).not.toContain("a warning");

  run.listener?.("home class: nc.vo.pub.lang.UFDate", "stdout");
  expect(consoleText(42)).toContain("home class: nc.vo.pub.lang.UFDate");

  handleDebugEvent(42, { kind: "terminated" });
  expect(run.stopped).toBe(1);
});

it("mirrors nothing when the session started its own debuggee", async () => {
  expect(await startSession(attach, { runConfig: null as never })).toBe(42);
  expect(run.listener).toBeNull();
  expect(consoleText(42)).toBe("");
});
