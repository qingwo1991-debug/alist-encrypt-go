import { _ as _export_sfc, d as defineComponent, B as computed, i as openBlock, j as createElementBlock, l as createBaseVNode, t as toDisplayString, m as unref, C as createStaticVNode, x as pushScopeId, y as popScopeId, b as createTextVNode } from "./index-1a909033.js";
const _imports_0 = "" + new URL("../png/404-538aa4d7.png", import.meta.url).href;
const _imports_1 = "" + new URL("../png/404_cloud-98e7ac66.png", import.meta.url).href;
const _404_vue_vue_type_style_index_0_scoped_31896b96_lang = "";
const _withScopeId = (n) => (pushScopeId("data-v-31896b96"), n = n(), popScopeId(), n);
const _hoisted_1 = { class: "wscn-http404-container" };
const _hoisted_2 = { class: "wscn-http404" };
const _hoisted_3 = /* @__PURE__ */ createStaticVNode('<div class="pic-404" data-v-31896b96><img class="pic-404__parent" src="' + _imports_0 + '" alt="404" data-v-31896b96><img class="pic-404__child left" src="' + _imports_1 + '" alt="404" data-v-31896b96><img class="pic-404__child mid" src="' + _imports_1 + '" alt="404" data-v-31896b96><img class="pic-404__child right" src="' + _imports_1 + '" alt="404" data-v-31896b96></div>', 1);
const _hoisted_4 = { class: "bullshit" };
const _hoisted_5 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("div", { class: "bullshit__oops" }, "OOPS!", -1));
const _hoisted_6 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("div", { class: "bullshit__info" }, [
  /* @__PURE__ */ createTextVNode(" All rights reserved "),
  /* @__PURE__ */ createBaseVNode("a", {
    style: { "color": "#20a0ff" },
    href: "https://wallstreetcn.com",
    target: "_blank"
  }, "wallstreetcn")
], -1));
const _hoisted_7 = { class: "bullshit__headline" };
const _hoisted_8 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("div", { class: "bullshit__info" }, " Please check that the URL you entered is correct, or click the button below to return to the homepage. ", -1));
const _hoisted_9 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("a", {
  href: "",
  class: "bullshit__return-home"
}, "Back to home", -1));
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "404",
  setup(__props) {
    const message = computed(() => {
      return "The webmaster said that you can not enter this page...";
    });
    return (_ctx, _cache) => {
      return openBlock(), createElementBlock("div", _hoisted_1, [
        createBaseVNode("div", _hoisted_2, [
          _hoisted_3,
          createBaseVNode("div", _hoisted_4, [
            _hoisted_5,
            _hoisted_6,
            createBaseVNode("div", _hoisted_7, toDisplayString(unref(message)), 1),
            _hoisted_8,
            _hoisted_9
          ])
        ])
      ]);
    };
  }
});
const _404 = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-31896b96"]]);
export {
  _404 as default
};
