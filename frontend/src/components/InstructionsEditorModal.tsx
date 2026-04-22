import { useEffect, useState } from "react";
import { X, Save, FileText } from "lucide-react";
import { useEditor, EditorContent } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import { Markdown } from "tiptap-markdown";
import { send, subscribe } from "../hooks/useIPC";

type Scope = "global" | "folder";

const SCOPE_LABEL: Record<Scope, string> = {
  global: "Global instructions",
  folder: "Folder instructions",
};

const SCOPE_HINT: Record<Scope, string> = {
  global:
    "Applies to every thClaws session on this machine. Stored at ~/.config/thclaws/AGENTS.md.",
  folder:
    "Applies only to the current project. Stored as AGENTS.md in the working directory.",
};

export function InstructionsEditorModal({
  scope,
  onClose,
}: {
  scope: Scope;
  onClose: () => void;
}) {
  const [path, setPath] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [flash, setFlash] = useState<{ ok: boolean; msg: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        // A few starter kit defaults get in the way of a plain-markdown
        // workflow — leave them on but let Markdown own the I/O.
      }),
      Markdown.configure({
        transformPastedText: true,
        transformCopiedText: true,
      }),
    ],
    content: "",
    editorProps: {
      attributes: {
        class:
          "prose prose-invert prose-sm max-w-none focus:outline-none min-h-[320px] px-4 py-3",
      },
    },
  });

  // Load content once, then subscribe for the round-trip of save results.
  useEffect(() => {
    const unsub = subscribe((msg) => {
      if (msg.type === "instructions_content" && msg.scope === scope) {
        if (typeof msg.path === "string") setPath(msg.path);
        if (editor) {
          editor.commands.setContent((msg.content as string) ?? "");
          editor.commands.focus("end");
        }
        setLoaded(true);
      } else if (msg.type === "instructions_save_result" && msg.scope === scope) {
        setBusy(false);
        setFlash({
          ok: Boolean(msg.ok),
          msg: msg.ok ? `Saved → ${msg.path}` : `Save failed: ${msg.error ?? "unknown error"}`,
        });
        setTimeout(() => setFlash(null), 3000);
      }
    });
    send({ type: "instructions_get", scope });
    return unsub;
  }, [scope, editor]);

  const handleSave = () => {
    if (!editor) return;
    setBusy(true);
    // tiptap-markdown exposes storage.markdown.getMarkdown()
    const md: string =
      (editor.storage as { markdown?: { getMarkdown: () => string } })
        .markdown?.getMarkdown() ?? "";
    send({ type: "instructions_save", scope, content: md });
  };

  return (
    <div
      className="fixed inset-0 flex items-center justify-center z-50"
      style={{ background: "var(--modal-backdrop)" }}
      onClick={onClose}
    >
      <div
        className="rounded-lg shadow-2xl max-w-3xl w-full mx-4 max-h-[85vh] flex flex-col"
        style={{ background: "var(--bg-secondary)", border: "1px solid var(--border)" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between p-4 border-b"
          style={{ borderColor: "var(--border)" }}
        >
          <div className="flex items-center gap-2">
            <FileText size={16} style={{ color: "var(--accent)" }} />
            <div>
              <h2
                className="text-sm font-semibold"
                style={{ color: "var(--text-primary)" }}
              >
                {SCOPE_LABEL[scope]}
              </h2>
              <div
                className="font-mono"
                style={{ color: "var(--text-secondary)", fontSize: "10px" }}
              >
                {path ?? SCOPE_HINT[scope]}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-white/10"
            style={{ color: "var(--text-secondary)" }}
            title="Close"
          >
            <X size={14} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loaded ? (
            <EditorContent editor={editor} />
          ) : (
            <div
              className="px-4 py-8 text-center text-xs"
              style={{ color: "var(--text-secondary)" }}
            >
              Loading…
            </div>
          )}
        </div>

        <div
          className="flex items-center justify-between p-3 border-t"
          style={{ borderColor: "var(--border)" }}
        >
          <div
            className="text-[10px] flex-1 mr-3 truncate"
            style={{
              color: flash
                ? flash.ok
                  ? "var(--accent)"
                  : "var(--danger, #e06c75)"
                : "var(--text-secondary)",
            }}
          >
            {flash ? flash.msg : SCOPE_HINT[scope]}
          </div>
          <div className="flex gap-2 shrink-0">
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded text-xs"
              style={{
                background: "var(--bg-primary)",
                color: "var(--text-secondary)",
                border: "1px solid var(--border)",
              }}
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={!editor || busy}
              className="px-3 py-1.5 rounded text-xs font-medium flex items-center gap-1"
              style={{
                background: "var(--accent)",
                color: "#fff",
                opacity: editor && !busy ? 1 : 0.4,
                cursor: editor && !busy ? "pointer" : "not-allowed",
              }}
            >
              <Save size={12} /> Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
