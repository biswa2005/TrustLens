import { PillLink } from "@/components/ui/Pill";
import { Eyebrow } from "@/components/ui/Eyebrow";

export default function NotFoundPage() {
  return (
    <section className="mx-auto flex min-h-[60vh] max-w-xl flex-col items-center justify-center gap-6 px-5 py-24 text-center">
      <Eyebrow dot="#8B95A7">404 · INCONCLUSIVE</Eyebrow>
      <h1 className="text-5xl font-extrabold tracking-[-0.045em]">
        This page could not be verified.
      </h1>
      <p className="text-fg-2">The address you followed doesn’t exist on TrustLens.</p>
      <PillLink to="/" arrow>
        Back to home
      </PillLink>
    </section>
  );
}
