import { sidebar } from "vuepress-theme-hope";

// @ts-ignore
export const zhSidebar = sidebar({
  "/xmxj/": [
    {
      icon: "discover",
      text: "概览",
      prefix: "gl/",
      link: "gl/",
      children: [
        "js","gn","gxls"
      ],
    },
    {
      text: "快速开始",
      icon: "note",
      prefix: "ksks/",
      link: "ksks/",
      children: [
        "hjdj","azpz","sy"
      ],
    },
    {
      text: "功能模块",
      icon: "note",
      prefix: "gmmk/",
      link: "gmmk/",
      children: ["hdxj","qdxj"]
    }
  ],
});