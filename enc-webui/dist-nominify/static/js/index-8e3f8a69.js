import { d as defineComponent, ab as storeToRefs, e as useBasicStore, i as openBlock, j as createElementBlock, l as createBaseVNode } from "./index-1a909033.js";
const _hoisted_1 = { class: "scroll-y" };
const _hoisted_2 = /* @__PURE__ */ createBaseVNode("h3", { class: "mb-20px" }, "功能", -1);
const _hoisted_3 = /* @__PURE__ */ createBaseVNode("div", { class: "rowSS" }, "文件可以在线加密解密", -1);
const _hoisted_4 = [
  _hoisted_2,
  _hoisted_3
];
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "index",
  setup(__props) {
    storeToRefs(useBasicStore());
    return (_ctx, _cache) => {
      return openBlock(), createElementBlock("div", _hoisted_1, _hoisted_4);
    };
  }
});
export {
  _sfc_main as default
};
