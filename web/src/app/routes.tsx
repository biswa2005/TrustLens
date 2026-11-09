import { createBrowserRouter } from "react-router";
import { RootLayout } from "@/components/layout/RootLayout";
import HomePage from "@/pages/HomePage";
import AboutPage from "@/pages/AboutPage";
import NotFoundPage from "@/pages/NotFoundPage";

export const router = createBrowserRouter(
  [
    {
      path: "/",
      Component: RootLayout,
      children: [
        { index: true, Component: HomePage },
        { path: "about", Component: AboutPage },
        { path: "*", Component: NotFoundPage },
      ],
    },
  ],
  { basename: import.meta.env.BASE_URL.replace(/\/$/, "") || "/" },
);
