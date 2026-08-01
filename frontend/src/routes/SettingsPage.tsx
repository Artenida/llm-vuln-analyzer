import { useEffect, useState } from "react";
import {
  useClearApiKey,
  useSaveApiKey,
  useSaveSettings,
  useSettings,
  useTestApiKey,
} from "@/api/hooks";
import type { ApiKeyStatus, SettingsResponse, UISettings } from "@/api/types";
import {
  Badge,
  Button,
  Card,
  DirectoryPicker,
  Field,
  NumberInput,
  QueryBoundary,
  Select,
  TextInput,
  Toggle,
} from "@/components";
import "./SettingsPage.css";

/** Unsaved edits, so navigating away mid-change does not discard them. */
const DRAFT_KEY = "vulnanalyzer.settings-draft.v1";

export function SettingsPage() {
  const { data, isLoading, error } = useSettings();

  return (
    <div className="stack">
      <div className="page-title">
        <h1>Settings</h1>
        <span className="page-subtitle">
          Your workspace, your API key, and the defaults new analyses start from.
        </span>
      </div>

      <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={5}>
        {(payload) => <SettingsBody data={payload} />}
      </QueryBoundary>
    </div>
  );
}

function readDraft(): Partial<UISettings> | null {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    return raw ? (JSON.parse(raw) as Partial<UISettings>) : null;
  } catch {
    return null;
  }
}

function SettingsBody({ data }: { data: SettingsResponse }) {
  // An unsaved draft outlives navigation. Previously any edit was wiped the
  // moment you left the page — and worse, a background refetch of the settings
  // query could clobber it while you were still typing.
  const [draft, setDraft] = useState<UISettings>(() => ({
    ...data.settings,
    ...(readDraft() ?? {}),
  }));
  const [dirty, setDirty] = useState(() => readDraft() !== null);
  const [picking, setPicking] = useState(false);
  const save = useSaveSettings();

  // Only adopt server state when there is nothing unsaved to lose.
  useEffect(() => {
    if (!dirty) setDraft(data.settings);
  }, [data.settings, dirty]);

  function update<K extends keyof UISettings>(key: K, value: UISettings[K]) {
    setDraft((previous) => {
      const next = { ...previous, [key]: value };
      try {
        localStorage.setItem(DRAFT_KEY, JSON.stringify(next));
      } catch {
        /* private mode — losing draft persistence is not worth an error */
      }
      return next;
    });
    setDirty(true);
  }

  function discard() {
    localStorage.removeItem(DRAFT_KEY);
    setDraft(data.settings);
    setDirty(false);
  }

  function commit() {
    save.mutate(draft, {
      onSuccess: () => {
        localStorage.removeItem(DRAFT_KEY);
        setDirty(false);
      },
    });
  }

  const workspaceChanged = draft.results_root !== data.settings.results_root;

  return (
    <div className="stack">
      <Card
        title="Workspace"
        description="One folder holds everything: your analysis results and your API key. Move the folder and both move with it."
        actions={
          <div className="row">
            {dirty && <span className="settings__dirty">unsaved changes</span>}
            {dirty && (
              <Button variant="ghost" onClick={discard}>
                Discard
              </Button>
            )}
            <Button variant="primary" disabled={!dirty || save.isPending} onClick={commit}>
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
        }
      >
        <Field
          label="Workspace folder"
          hint={
            workspaceChanged
              ? "Press Save before adding a key — the key is written into the saved workspace."
              : "Results are saved here, and your API key is stored here as a .openai.key file."
          }
        >
          <div className="settings__pathrow">
            <TextInput
              value={draft.results_root}
              onChange={(value) => update("results_root", value)}
            />
            <Button onClick={() => setPicking(true)}>Browse…</Button>
          </div>
        </Field>
      </Card>

      <ApiKeyCard
        keys={data.api_keys}
        workspace={data.environment.workspace}
        blocked={workspaceChanged}
      />

      <Card
        title="Analysis defaults"
        description="What the Analyze page starts with. Every run can still override them."
        actions={
          <div className="row">
            {dirty && <span className="settings__dirty">unsaved changes</span>}
            <Button variant="primary" disabled={!dirty || save.isPending} onClick={commit}>
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
        }
      >
        <div className="settings__grid">
          <Field
            label="Default mode"
            hint="Agentic explores the call graph before each verdict — more accurate, several API calls per function. Semantic makes one pass per function."
          >
            <Select
              value={draft.react ? "react" : "semantic"}
              onChange={(value) => update("react", value === "react")}
              options={[
                { value: "react", label: "Agentic — ReAct loop" },
                { value: "semantic", label: "Semantic — call graph context" },
              ]}
            />
          </Field>

          <Field label="Model" hint="Which OpenAI model new analyses use.">
            <Select
              value={draft.model}
              onChange={(value) => update("model", value)}
              options={[
                { value: "o4-mini", label: "o4-mini" },
                { value: "gpt-4o-mini", label: "gpt-4o-mini" },
              ]}
            />
          </Field>

          <Field
            label="Max ReAct steps"
            hint="How many times the agent may consult the call graph before it has to answer."
          >
            <NumberInput
              value={draft.max_steps}
              onChange={(value) => update("max_steps", value ?? 1)}
              min={1}
            />
          </Field>

          <Field
            label="Max function lines"
            hint="Functions longer than this are skipped — and always reported, never silently dropped."
          >
            <NumberInput
              value={draft.max_function_lines}
              onChange={(value) => update("max_function_lines", value ?? 200)}
              min={10}
            />
          </Field>

          <Field
            label="Default budget (USD)"
            hint="A spending ceiling pre-filled on every run. Leave empty for none."
          >
            <NumberInput
              value={draft.budget_usd}
              onChange={(value) => update("budget_usd", value)}
              min={0}
              step={0.5}
              placeholder="no ceiling"
            />
          </Field>

          <Field label="API key to use" hint="Which saved key new analyses are billed to.">
            <Select
              value={draft.api_key_alias}
              onChange={(value) => update("api_key_alias", value)}
              options={
                data.api_keys.length > 0
                  ? data.api_keys.map((key) => ({ value: key.alias, label: key.alias }))
                  : [{ value: "default", label: "default" }]
              }
            />
          </Field>

          <div className="settings__wide">
            <Toggle
              checked={draft.visualize}
              onChange={(value) => update("visualize", value)}
              label="Build the call graph view by default"
              hint="The interactive graph shown on the Results page."
            />
          </div>
        </div>
      </Card>

      <Card title="About this install" description="Read-only.">
        <dl className="kv">
          <dt>Workspace</dt>
          <dd>
            {data.environment.workspace}{" "}
            {!data.environment.workspace_exists && (
              <span className="faint">(created on first use)</span>
            )}
          </dd>
          <dt>Key file</dt>
          <dd>{data.environment.key_file}</dd>
          <dt>Cost ledger</dt>
          <dd>
            {data.environment.ledger_path}{" "}
            {!data.environment.ledger_exists && (
              <span className="faint">(nothing spent yet)</span>
            )}
          </dd>
          <dt>Python</dt>
          <dd>
            {data.environment.python} — {data.environment.python_executable}
          </dd>
        </dl>
      </Card>

      {picking && (
        <DirectoryPicker
          title="Select a workspace folder"
          initialPath={draft.results_root}
          allowCreate
          onCancel={() => setPicking(false)}
          onPick={(path) => {
            update("results_root", path);
            setPicking(false);
          }}
        />
      )}
    </div>
  );
}

function ApiKeyCard({
  keys,
  workspace,
  blocked,
}: {
  keys: ApiKeyStatus[];
  workspace: string;
  blocked: boolean;
}) {
  const [value, setValue] = useState("");
  const [alias, setAlias] = useState("default");
  const saveKey = useSaveApiKey();
  const clearKey = useClearApiKey();
  const testKey = useTestApiKey();

  const current = keys.find((key) => key.alias === alias);
  const anyConfigured = keys.some((key) => key.configured);

  return (
    <Card
      title="OpenAI API key"
      description="Needed to analyse anything. Get one at platform.openai.com → API keys."
    >
      <div className="stack">
        {!anyConfigured && (
          <div className="note">
            <span className="note__label">No key yet</span>
            Paste your OpenAI key below and press <strong>Save key</strong>. It is
            stored in your workspace folder, so nothing is written into the
            application itself.
          </div>
        )}

        {keys.filter((key) => key.configured).length > 0 && (
          <div className="settings__keys">
            {keys
              .filter((key) => key.configured)
              .map((key) => (
                <div key={key.alias} className="settings__key">
                  <div className="row">
                    <Badge variant="ok">saved</Badge>
                    <span className="mono">{key.alias}</span>
                    <span className="mono faint">{key.masked}</span>
                  </div>
                  <span className="settings__keysource">
                    {key.source === "workspace" ? (
                      <span title={key.key_file}>in your workspace</span>
                    ) : (
                      <span title={key.env_var}>
                        from the environment ({key.env_var})
                      </span>
                    )}
                  </span>
                </div>
              ))}
          </div>
        )}

        {blocked && (
          <div className="note">
            <span className="note__label">Save the workspace first</span>
            You changed the workspace folder but have not saved it. Save it above,
            then add the key — otherwise it would be written to the old folder.
          </div>
        )}

        <div className="settings__keyform">
          <Field
            label="Key"
            hint={`Stored as plain text in ${workspace}. Anyone with access to that folder can read it.`}
          >
            <TextInput
              value={value}
              onChange={setValue}
              type="password"
              placeholder="sk-…"
            />
          </Field>
          <Field
            label="Name"
            hint="Leave as “default” unless you keep more than one key."
          >
            <TextInput value={alias} onChange={setAlias} placeholder="default" />
          </Field>
          <div className="settings__keyactions">
            <Button
              variant="primary"
              disabled={!value.trim() || saveKey.isPending || blocked}
              onClick={() =>
                saveKey.mutate({ value, alias }, { onSuccess: () => setValue("") })
              }
            >
              {saveKey.isPending ? "Saving…" : "Save key"}
            </Button>
            <Button
              disabled={!current?.configured || testKey.isPending}
              onClick={() => testKey.mutate(alias)}
            >
              {testKey.isPending ? "Checking…" : "Check it works"}
            </Button>
            <Button
              variant="danger"
              disabled={current?.source !== "workspace"}
              title={
                current?.source === "environment"
                  ? "This key comes from an environment variable, not from your workspace, so it cannot be removed here."
                  : undefined
              }
              onClick={() => clearKey.mutate(alias)}
            >
              Remove
            </Button>
          </div>
        </div>

        {saveKey.error && (
          <div className="note note--error">
            <span className="note__label">Could not save</span>
            {(saveKey.error as Error).message}
          </div>
        )}

        {testKey.data && (
          <div className={testKey.data.ok ? "note note--ok" : "note note--error"}>
            <span className="note__label">
              {testKey.data.ok ? "Key works" : "Key rejected"}
            </span>
            {testKey.data.detail}
          </div>
        )}
      </div>
    </Card>
  );
}
