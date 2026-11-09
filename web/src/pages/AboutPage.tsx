import { AboutHero } from "@/components/about/AboutHero";
import { Mission } from "@/components/about/Mission";
import { VideoShowcase } from "@/components/about/VideoShowcase";
import { Workflow } from "@/components/about/Workflow";
import { TechArchitecture } from "@/components/about/TechArchitecture";
import { Principles } from "@/components/about/Principles";
import { AboutCta } from "@/components/about/AboutCta";

export default function AboutPage() {
  return (
    <>
      <AboutHero />
      <Mission />
      <VideoShowcase />
      <Workflow />
      <TechArchitecture />
      <Principles />
      <AboutCta />
    </>
  );
}
