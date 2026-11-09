import { createBrowserRouter } from "react-router";
import { RootLayout } from "@/components/layout/RootLayout";
import HomePage from "@/pages/HomePage";
import AboutPage from "@/pages/AboutPage";
import InvestigatePage from "@/pages/InvestigatePage";
import InvestigationsPage from "@/pages/InvestigationsPage";
import NotFoundPage from "@/pages/NotFoundPage";

export const router = createBrowserRouter(
  [
    {
      path: "/",
      Component: RootLayout,
      children: [
        { index: true, Component: HomePage },
        { path: "about", Component: AboutPage },
        { path: "investigate", Component: InvestigatePage },
        { path: "investigations", Component: InvestigationsPage },
        { path: "*", Component: NotFoundPage },
      ],
    },
  ],
  { basename: import.meta.env.BASE_URL.replace(/\/$/, "") || "/" },
);
