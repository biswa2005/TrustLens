import { Hero } from "@/components/home/Hero";
import { Scanner } from "@/components/home/Scanner";
import { Telemetry } from "@/components/home/Telemetry";
import { Capabilities } from "@/components/home/Capabilities";
import { RiskClassification } from "@/components/home/RiskClassification";
import { TrustRegistry } from "@/components/home/TrustRegistry";
import { FinalCta } from "@/components/home/FinalCta";

export default function HomePage() {
  return (
    <>
      <Hero />
      <Telemetry />
      <Scanner />
      <Capabilities />
      <RiskClassification />
      <TrustRegistry />
      <FinalCta />
    </>
  );
}
