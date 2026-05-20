import { _ as _export_sfc, d as defineComponent, r as reactive, u as useRoute, a as useRouter, D as toRefs, h as resolveComponent, i as openBlock, j as createElementBlock, c as createVNode, k as withCtx, b as createTextVNode, l as createBaseVNode, q as withModifiers, m as unref, E as isRef, x as pushScopeId, y as popScopeId } from "./index-1a909033.js";
const errGif = "" + new URL("../gif/401-a61ddb94.gif", import.meta.url).href;
const _401_vue_vue_type_style_index_0_scoped_16256ffe_lang = "";
const _withScopeId = (n) => (pushScopeId("data-v-16256ffe"), n = n(), popScopeId(), n);
const _hoisted_1 = { class: "errPage-container" };
const _hoisted_2 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("h1", { class: "text-jumbo text-ginormous" }, "Oops!", -1));
const _hoisted_3 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("a", {
  href: "https://zh.airbnb.com/",
  target: "_blank"
}, "airbnb", -1));
const _hoisted_4 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("h2", null, "你没有权限去该页面", -1));
const _hoisted_5 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("h6", null, "如有不满请联系你领导", -1));
const _hoisted_6 = { class: "list-unstyled" };
const _hoisted_7 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("li", null, "或者你可以去:", -1));
const _hoisted_8 = { class: "link-type" };
const _hoisted_9 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("li", { class: "link-type" }, [
  /* @__PURE__ */ createBaseVNode("a", { href: "https://www.taobao.com/" }, "随便看看")
], -1));
const _hoisted_10 = ["src"];
const _hoisted_11 = ["src"];
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "401",
  setup(__props) {
    const state = reactive({
      errGif: `${errGif}?${Date.now()}`,
      ewizardClap: "https://wpimg.wallstcn.com/007ef517-bafd-4066-aae4-6883632d9646",
      dialogVisible: false
    });
    const route = useRoute();
    const router = useRouter();
    const back = () => {
      if (route.query.noGoBack) {
        router.push({ path: "/dashboard" });
      } else {
        router.go(-1);
      }
    };
    const { ewizardClap, dialogVisible } = toRefs(state);
    return (_ctx, _cache) => {
      const _component_el_button = resolveComponent("el-button");
      const _component_router_link = resolveComponent("router-link");
      const _component_el_col = resolveComponent("el-col");
      const _component_el_row = resolveComponent("el-row");
      const _component_el_dialog = resolveComponent("el-dialog");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        createVNode(_component_el_button, {
          icon: "el-icon-arrow-left",
          class: "pan-back-btn",
          onClick: back
        }, {
          default: withCtx(() => [
            createTextVNode("返回")
          ]),
          _: 1
        }),
        createVNode(_component_el_row, null, {
          default: withCtx(() => [
            createVNode(_component_el_col, { span: 12 }, {
              default: withCtx(() => [
                _hoisted_2,
                createTextVNode(" gif来源 "),
                _hoisted_3,
                createTextVNode(" 页面 "),
                _hoisted_4,
                _hoisted_5,
                createBaseVNode("ul", _hoisted_6, [
                  _hoisted_7,
                  createBaseVNode("li", _hoisted_8, [
                    createVNode(_component_router_link, { to: "/dashboard" }, {
                      default: withCtx(() => [
                        createTextVNode("回首页")
                      ]),
                      _: 1
                    })
                  ]),
                  _hoisted_9,
                  createBaseVNode("li", null, [
                    createBaseVNode("a", {
                      href: "#",
                      onClick: _cache[0] || (_cache[0] = withModifiers(($event) => dialogVisible.value = true, ["prevent"]))
                    }, "点我看图")
                  ])
                ])
              ]),
              _: 1
            }),
            createVNode(_component_el_col, { span: 12 }, {
              default: withCtx(() => [
                createBaseVNode("img", {
                  src: unref(errGif),
                  width: "313",
                  height: "428",
                  alt: "Girl has dropped her ice cream."
                }, null, 8, _hoisted_10)
              ]),
              _: 1
            })
          ]),
          _: 1
        }),
        createVNode(_component_el_dialog, {
          modelValue: unref(dialogVisible),
          "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => isRef(dialogVisible) ? dialogVisible.value = $event : null),
          title: "随便看"
        }, {
          default: withCtx(() => [
            createBaseVNode("img", {
              src: unref(ewizardClap),
              class: "pan-img"
            }, null, 8, _hoisted_11)
          ]),
          _: 1
        }, 8, ["modelValue"])
      ]);
    };
  }
});
const _401 = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-16256ffe"]]);
export {
  _401 as default
};
