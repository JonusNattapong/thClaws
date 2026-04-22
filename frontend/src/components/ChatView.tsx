import { useState, useRef, useEffect } from "react";
import { send, subscribe } from "../hooks/useIPC";
import { useTheme } from "../hooks/useTheme";
import logoDark from "../assets/thClaws-logo-dark.png";
import logoLight from "../assets/thClaws-logo-light.png";

type ChatMessage = {
  role: "user" | "assistant" | "tool" | "system";
  content: string;
  toolName?: string;
};

export function ChatView() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const { resolved: themeMode } = useTheme();

  useEffect(() => {
    const unsub = subscribe((msg) => {
      switch (msg.type) {
        case "chat_user_message":
          // Echo of a prompt the user submitted (possibly from the
          // Terminal tab — we render it as a user bubble either way).
          setMessages((prev) => [
            ...prev,
            { role: "user", content: msg.text as string },
          ]);
          break;
        case "chat_text_delta":
          setMessages((prev) => {
            const last = prev[prev.length - 1];
            if (last && last.role === "assistant") {
              return [
                ...prev.slice(0, -1),
                { ...last, content: last.content + (msg.text as string) },
              ];
            }
            return [...prev, { role: "assistant", content: msg.text as string }];
          });
          break;
        case "chat_tool_call":
          setMessages((prev) => [
            ...prev,
            {
              role: "tool",
              content: `Calling ${msg.name}...`,
              toolName: msg.name as string,
            },
          ]);
          break;
        case "chat_tool_result":
          setMessages((prev) => {
            const last = prev[prev.length - 1];
            if (last && last.role === "tool") {
              return [
                ...prev.slice(0, -1),
                {
                  ...last,
                  content: `${last.toolName} → ${(msg.output as string).slice(0, 200)}`,
                },
              ];
            }
            return prev;
          });
          break;
        case "chat_slash_output":
          setMessages((prev) => [
            ...prev,
            { role: "system", content: msg.text as string },
          ]);
          break;
        case "chat_done":
          setStreaming(false);
          break;
        case "new_session_ack":
          setMessages([]);
          setStreaming(false);
          break;
        case "chat_history_replaced":
          if (msg.messages && Array.isArray(msg.messages)) {
            setMessages(
              (msg.messages as { role: string; content: string }[]).map(
                (m) => ({
                  role:
                    m.role === "assistant"
                      ? "assistant"
                      : m.role === "tool"
                        ? "tool"
                        : m.role === "system"
                          ? "system"
                          : "user",
                  content: m.content,
                } as ChatMessage),
              ),
            );
            setStreaming(false);
          }
          break;
      }
    });
    return unsub;
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || streaming) return;
    const text = input.trim();
    setInput("");

    // /exit and /quit close the window — handle locally so we get the
    // window.close after the backend save round-trip. Everything else
    // (including /clear, /help, every other slash command) goes to the
    // shared session, which dispatches it and broadcasts the response
    // back as a `chat_slash_output` system bubble.
    const lower = text.toLowerCase();
    if (lower === "/exit" || lower === "/quit" || lower === "/q") {
      send({ type: "new_session" });
      setTimeout(() => window.close(), 200);
      return;
    }

    // Don't optimistically add the user bubble — the backend will echo
    // a `chat_user_message` back to us (it does so for both tabs). This
    // keeps a single source of truth about what's in the conversation.
    if (!text.startsWith("/")) setStreaming(true);
    send({ type: "shell_input", text });
  };

  return (
    <div className="flex flex-col h-full">
      {/* Messages */}
      <div
        className="flex-1 overflow-y-auto p-4 space-y-3"
        style={{ background: "var(--bg-primary)" }}
      >
        {messages.length === 0 && (
          <div
            className="flex flex-col items-center mt-20 select-none"
            style={{ color: "var(--text-secondary)" }}
          >
            <img
              src={themeMode === "light" ? logoLight : logoDark}
              alt="thClaws"
              className="mb-4 opacity-90"
              style={{ width: 280, height: 280 }}
              draggable={false}
            />
            <div className="text-sm">Chat mode — send a message to start</div>
          </div>
        )}
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex ${msg.role === "user" ? "justify-end" : msg.role === "system" ? "justify-center" : "justify-start"}`}
          >
            <div
              className="max-w-[80%] rounded-lg px-3 py-2 text-sm whitespace-pre-wrap"
              style={{
                background:
                  msg.role === "user"
                    ? "var(--chat-user-bg)"
                    : msg.role === "tool"
                      ? "var(--bg-tertiary)"
                      : msg.role === "system"
                        ? "transparent"
                        : "var(--bg-secondary)",
                color:
                  msg.role === "user"
                    ? "var(--chat-user-fg)"
                    : msg.role === "system"
                      ? "var(--text-secondary)"
                      : "var(--text-primary)",
                border:
                  msg.role === "tool" || msg.role === "system"
                    ? "1px solid var(--border)"
                    : "none",
                fontFamily:
                  msg.role === "tool" || msg.role === "system"
                    ? "Menlo, Monaco, monospace"
                    : "inherit",
                fontSize:
                  msg.role === "tool" || msg.role === "system" ? "12px" : "14px",
              }}
            >
              {msg.content}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form
        onSubmit={handleSubmit}
        className="flex gap-2 p-3 border-t"
        style={{
          background: "var(--bg-secondary)",
          borderColor: "var(--border)",
        }}
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={streaming ? "Waiting for response..." : "Type a message..."}
          disabled={streaming}
          className="flex-1 px-3 py-2 rounded text-sm outline-none"
          style={{
            background: "var(--bg-tertiary)",
            color: "var(--text-primary)",
            border: "1px solid var(--border)",
          }}
        />
        <button
          type="submit"
          disabled={streaming || !input.trim()}
          className="px-4 py-2 rounded text-sm font-medium transition-colors"
          style={{
            background: streaming ? "var(--bg-tertiary)" : "var(--accent)",
            color: streaming ? "var(--text-secondary)" : "var(--accent-fg)",
            cursor: streaming ? "not-allowed" : "pointer",
          }}
        >
          Send
        </button>
      </form>
    </div>
  );
}
