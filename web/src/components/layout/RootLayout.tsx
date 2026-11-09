import { useEffect } from "react";
import { useLocation, useOutlet } from "react-router";
import { AnimatePresence, MotionConfig, motion } from "motion/react";
import { AnnouncementBar } from "./AnnouncementBar";
import { Header } from "./Header";
import { Footer } from "./Footer";

function useHashScroll() {
  const location = useLocation();
  useEffect(() => {
    if (!location.hash) {
      window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior });
      return;
    }
    const id = decodeURIComponent(location.hash.slice(1));
    let tries = 0;
    let timer: ReturnType<typeof setTimeout>;
    // Wait for the incoming page to mount after the route transition.
    const attempt = () => {
      const el = document.getElementById(id);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      else if (tries++ < 20) timer = setTimeout(attempt, 60);
    };
    timer = setTimeout(attempt, 30);
    return () => clearTimeout(timer);
  }, [location.key, location.hash]);
}

export function RootLayout() {
  const location = useLocation();
  const outlet = useOutlet();
  useHashScroll();

  return (
    <MotionConfig reducedMotion="user">
      <div className="flex min-h-svh flex-col bg-ink">
        <AnnouncementBar />
        <Header />
        <AnimatePresence mode="wait" initial={false}>
          <motion.main
            key={location.pathname}
            className="flex-1"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
          >
            {outlet}
          </motion.main>
        </AnimatePresence>
        <Footer />
      </div>
    </MotionConfig>
  );
}
