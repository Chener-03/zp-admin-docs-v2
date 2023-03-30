import { navbar } from "vuepress-theme-hope";

export const zhNavbar = navbar([
  "/",
  { text: "项目详解", icon: "discover", link: "/xmxj/gl/" },
  { text: "项目实战", icon: "discover", link: "/demo/" },
  { text: "更新历史", icon: "discover", link: "/demo/" },
  { text: "仓库地址", icon: "discover", link: "/demo/" },
  {
    text: "在线体验",
    icon: "creative",
    children: [
      {
        text: "Web版",
        icon: "creative",
        link: "http://zpdemo.chener.xyz/",
      },
      {
        text: "安卓版",
        icon: "config",
        link: "http://zpdemo.chener.xyz/",
      },
      {
        text: "小程序",
        icon: "config",
        link: "http://zpdemo.chener.xyz/",
      },
    ],
  }
]);
