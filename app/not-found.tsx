import Link from "next/link";

export default function NotFound() {
  return (
    <main>
      <h1>Not found</h1>
      <p className="meta">
        No such page or agent instance in the current snapshot — it may have existed in an older
        one.
      </p>
      <p>
        <Link href="/">← Back to overview</Link>
      </p>
    </main>
  );
}
