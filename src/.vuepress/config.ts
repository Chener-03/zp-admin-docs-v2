import { defineUserConfig } from "vuepress";
import theme from "./theme.js";

export default defineUserConfig({
  base: "/",
  port:8088,

  locales: {
    "/": {
      lang: "zh-CN",
      title: "ZP-ADMIN",
      description: "ZP-ADMIN 中文文档",
    },
    "/en/": {
      lang: "en-US",
      title: "Docs Demo",
      description: "A docs demo for vuepress-theme-hope",
    },
  },

  theme,

  // Enable it with pwa
  // shouldPrefetch: false,
});
