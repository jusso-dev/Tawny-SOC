"use client";

import { Search, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { type ChangeEvent, type FormEvent, useTransition } from "react";
import type { ThreatIntelSortDirection, ThreatIntelSortKey } from "@/lib/store";
import type { ThreatIntelMatch } from "@/lib/types";

type ThreatIntelControlsState = {
  direction: ThreatIntelSortDirection;
  page?: number;
  search: string;
  sort: ThreatIntelSortKey;
  sourceFeed: string;
  type: ThreatIntelMatch["type"] | "";
};

function threatIntelPath(state: ThreatIntelControlsState) {
  const params = new URLSearchParams();
  const search = state.search.trim();
  const page = state.page ?? 1;

  if (search) params.set("q", search);
  if (state.type) params.set("type", state.type);
  if (state.sourceFeed) params.set("sourceFeed", state.sourceFeed);
  if (state.sort !== "lastSeen") params.set("sort", state.sort);
  if (state.direction !== "desc") params.set("direction", state.direction);
  if (page > 1) params.set("page", String(page));

  const query = params.toString();
  return query ? `/threat-intel?${query}` : "/threat-intel";
}

function textField(formData: FormData, name: string) {
  const value = formData.get(name);
  return typeof value === "string" ? value : "";
}

export function ThreatIntelControls({
  direction,
  search,
  sort,
  sourceFeed,
  sourceFeedOptions,
  type,
  types,
}: {
  direction: ThreatIntelSortDirection;
  search: string;
  sort: ThreatIntelSortKey;
  sourceFeed: string;
  sourceFeedOptions: string[];
  type: ThreatIntelMatch["type"] | "";
  types: Array<ThreatIntelMatch["type"]>;
}) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  function navigate(form: HTMLFormElement, mode: "push" | "replace" = "push") {
    const formData = new FormData(form);
    const nextType = textField(formData, "type") as ThreatIntelMatch["type"] | "";
    const href = threatIntelPath({
      direction,
      page: 1,
      search: textField(formData, "q"),
      sort,
      sourceFeed: textField(formData, "sourceFeed"),
      type: types.includes(nextType as ThreatIntelMatch["type"]) ? nextType : "",
    });

    startTransition(() => {
      if (mode === "replace") {
        router.replace(href, { scroll: false });
        return;
      }

      router.push(href, { scroll: false });
    });
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    navigate(event.currentTarget);
  }

  function handleTypeChange(event: ChangeEvent<HTMLSelectElement>) {
    if (event.currentTarget.form) navigate(event.currentTarget.form, "replace");
  }

  function handleSourceFeedChange(event: ChangeEvent<HTMLSelectElement>) {
    if (event.currentTarget.form) navigate(event.currentTarget.form, "replace");
  }

  function handleReset() {
    startTransition(() => router.push("/threat-intel", { scroll: false }));
  }

  return (
    <form
      key={`${search}\u0000${type}\u0000${sourceFeed}`}
      className="intel-controls"
      action="/threat-intel"
      aria-busy={isPending}
      method="get"
      onSubmit={handleSubmit}
    >
      <label>
        <span>Search</span>
        <input name="q" defaultValue={search} placeholder="IOC, tag, source feed, or type" />
      </label>
      <label>
        <span>Type</span>
        <select name="type" defaultValue={type} onChange={handleTypeChange}>
          <option value="">All types</option>
          {types.map((iocType) => (
            <option key={iocType} value={iocType}>{iocType}</option>
          ))}
        </select>
      </label>
      <label>
        <span>Source feed</span>
        <select name="sourceFeed" defaultValue={sourceFeed} onChange={handleSourceFeedChange}>
          <option value="">All feeds</option>
          {sourceFeedOptions.map((feedName) => (
            <option key={feedName} value={feedName}>{feedName}</option>
          ))}
        </select>
      </label>
      <input type="hidden" name="sort" value={sort} />
      <input type="hidden" name="direction" value={direction} />
      <button className="primary-action" disabled={isPending} type="submit"><Search size={15} aria-hidden /> Search</button>
      <button className="filter-link" disabled={isPending} onClick={handleReset} type="button"><X size={15} aria-hidden /> Reset</button>
    </form>
  );
}
