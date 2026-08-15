import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { useDirListing, useFsRoots } from "@/api/hooks";
import { Button, TextInput } from "./Field";
import { ErrorState, Skeleton } from "./States";
import "./DirectoryPicker.css";

/**
 * Server-side folder picker.
 *
 * A web page cannot get an absolute path out of a native file dialog — an
 * `<input webkitdirectory>` yields relative names only. Since the backend runs
 * on this machine, listing directories server-side is the only way to turn
 * "select the folder" into a real path. See docs/frontend-plan.md §8.
 */
export function DirectoryPicker({
  initialPath,
  onPick,
  onCancel,
  title = "Select a folder",
  confirmLabel = "Use this folder",
  allowCreate = false,
  requireResultDir = false,
}: {
  initialPath?: string | null;
  onPick: (path: string) => void;
  onCancel: () => void;
  title?: string;
  confirmLabel?: string;
  allowCreate?: boolean;
  /**
   * Only allow picking a folder that already holds run artifacts. Used when
   * opening previous results, where any other folder is certain to be refused
   * by the server — better to say so in the dialog than after the click.
   */
  requireResultDir?: boolean;
}) {
  const { data: roots } = useFsRoots();
  const [path, setPath] = useState<string | null>(initialPath ?? null);
  const [typed, setTyped] = useState(initialPath ?? "");
  const [newFolder, setNewFolder] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const listing = useDirListing(path);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!path && roots && roots.length > 0) setPath(roots[0].path);
  }, [roots, path]);

  useEffect(() => {
    if (listing.data) setTyped(listing.data.path);
  }, [listing.data]);

  function go(next: string) {
    setPath(next);
  }

  async function createFolder() {
    if (!newFolder.trim() || !listing.data) return;
    const target = `${listing.data.path.replace(/[\\/]$/, "")}/${newFolder.trim()}`;
    try {
      await api.post("/fs/mkdir", { path: target });
      setCreateError(null);
      setNewFolder("");
      // The parent listing is now stale — the new folder has to appear in it.
      await queryClient.invalidateQueries({ queryKey: ["fs-list"] });
      setPath(target);
    } catch (error) {
      setCreateError((error as Error).message);
    }
  }

  return (
    <div className="picker" role="dialog" aria-modal="true" aria-label={title}>
      <div className="picker__backdrop" onClick={onCancel} />
      <div className="picker__panel">
        <header className="picker__header">
          <h3>{title}</h3>
          <Button variant="ghost" onClick={onCancel}>
            ✕
          </Button>
        </header>

        <div className="picker__roots">
          {roots?.map((root) => (
            <button
              key={root.path}
              type="button"
              className="picker__root"
              onClick={() => go(root.path)}
            >
              {root.label}
            </button>
          ))}
        </div>

        <div className="picker__pathbar">
          <TextInput
            value={typed}
            onChange={setTyped}
            placeholder="Type or paste a path"
            onKeyDown={(event) => {
              if (event.key === "Enter") go(typed);
            }}
          />
          <Button onClick={() => go(typed)}>Go</Button>
        </div>

        <div className="picker__list">
          {listing.data?.parent && (
            <button
              type="button"
              className="picker__entry picker__entry--up"
              onClick={() => go(listing.data!.parent!)}
            >
              <span className="picker__glyph">↑</span> ..
            </button>
          )}

          {listing.isLoading && <Skeleton rows={5} height={22} />}
          {listing.error && <ErrorState error={listing.error} />}

          {listing.data?.entries.length === 0 && !listing.isLoading && (
            <p className="picker__empty">No sub-folders here.</p>
          )}

          {listing.data?.entries.map((entry) => (
            <button
              key={entry.path}
              type="button"
              className="picker__entry"
              onDoubleClick={() => go(entry.path)}
              onClick={() => go(entry.path)}
              title={entry.path}
            >
              <span className="picker__glyph">▸</span>
              <span className="picker__name">{entry.name}</span>
              {/* Marks folders that already hold results, so an output folder
                  is not accidentally reused and overwritten. */}
              {entry.is_result_dir && <span className="picker__tag">results</span>}
            </button>
          ))}
        </div>

        {allowCreate && listing.data && (
          <div className="picker__create">
            <TextInput
              value={newFolder}
              onChange={setNewFolder}
              placeholder="New folder name"
              onKeyDown={(event) => {
                if (event.key === "Enter") void createFolder();
              }}
            />
            <Button onClick={() => void createFolder()} disabled={!newFolder.trim()}>
              Create
            </Button>
          </div>
        )}

        {createError && <p className="picker__error">{createError}</p>}

        {requireResultDir && listing.data && !listing.data.is_result_dir && (
          <p className="picker__hint">
            This folder holds no results. Open the folder a run wrote to — it
            contains <span className="mono">analysis.json</span>. Folders tagged{" "}
            <span className="picker__tag">results</span> above are the ones.
          </p>
        )}

        <footer className="picker__footer">
          <span className="picker__current mono" title={listing.data?.path ?? typed}>
            {listing.data?.path ?? typed ?? "—"}
          </span>
          <div className="row">
            <Button variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={() => onPick(listing.data?.path ?? typed)}
              disabled={
                (!listing.data && !typed) ||
                (requireResultDir && !listing.data?.is_result_dir)
              }
            >
              {confirmLabel}
            </Button>
          </div>
        </footer>
      </div>
    </div>
  );
}
