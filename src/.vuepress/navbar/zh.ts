import { navbar } from "vuepress-theme-hope";

export const zhNavbar = navbar([
  "/",
  { text: "项目详解", icon: "alias", link: "/xmxj/gl/" },
  { text: "项目实战", icon: "advance", link: "/xmsz/" },
  { text: "更新历史", icon: "result", link: "/xmxj/gl/gxls" },
  { text: "仓库地址", icon: "branch", link: "/xmxj/gl/js.html#项目地址" },
  {
    text: "在线体验",
    icon: "creative",
    children: [
      {
        text: "Web版",
        icon: "computer",
        link: "http://zpdemo.chener.xyz/",
      },
      {
        text: "安卓版",
        icon: "android",
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
