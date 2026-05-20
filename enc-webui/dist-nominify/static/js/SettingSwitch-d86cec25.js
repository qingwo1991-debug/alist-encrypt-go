import { d as defineComponent, ab as storeToRefs, e as useBasicStore, h as resolveComponent, i as openBlock, j as createElementBlock, l as createBaseVNode, b as createTextVNode, c as createVNode, m as unref } from "./index-1a909033.js";
const _hoisted_1 = { class: "scroll-y" };
const _hoisted_2 = /* @__PURE__ */ createBaseVNode("h3", { class: "mb-20px" }, "props operate demo of settings.js", -1);
const _hoisted_3 = { class: "rowSS" };
const _hoisted_4 = { class: "mb-10px" };
const _hoisted_5 = /* @__PURE__ */ createBaseVNode("div", { class: "font-bold text-20px" }, "page layout related", -1);
const _hoisted_6 = { class: "mt-20px" };
const _hoisted_7 = { class: "mt-30px" };
const _hoisted_8 = { class: "mt-30px" };
const _hoisted_9 = { class: "mt-30px" };
const _hoisted_10 = { class: "mt-30px" };
const _hoisted_11 = { class: "mt-30px" };
const _hoisted_12 = { class: "mt-30px" };
const _hoisted_13 = { class: "mb-10px ml-60px" };
const _hoisted_14 = /* @__PURE__ */ createBaseVNode("div", { class: "font-bold text-20px" }, "page animation related", -1);
const _hoisted_15 = /* @__PURE__ */ createBaseVNode("div", { class: "mt-20px" }, 'mainNeedAnimation：places to "settings file" for setting', -1);
const _hoisted_16 = { class: "mt-30px" };
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "SettingSwitch",
  setup(__props) {
    const { settings } = storeToRefs(useBasicStore());
    return (_ctx, _cache) => {
      const _component_el_switch = resolveComponent("el-switch");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        _hoisted_2,
        createBaseVNode("div", _hoisted_3, [
          createBaseVNode("div", _hoisted_4, [
            _hoisted_5,
            createBaseVNode("div", _hoisted_6, [
              createTextVNode(" sidebarLogo： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).sidebarLogo,
                "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => unref(settings).sidebarLogo = $event)
              }, null, 8, ["modelValue"])
            ]),
            createBaseVNode("div", _hoisted_7, [
              createTextVNode(" showNavbarTitle： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).showNavbarTitle,
                "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => unref(settings).showNavbarTitle = $event)
              }, null, 8, ["modelValue"])
            ]),
            createBaseVNode("div", _hoisted_8, [
              createTextVNode(" ShowDropDown： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).ShowDropDown,
                "onUpdate:modelValue": _cache[2] || (_cache[2] = ($event) => unref(settings).ShowDropDown = $event)
              }, null, 8, ["modelValue"])
            ]),
            createBaseVNode("div", _hoisted_9, [
              createTextVNode(" showHamburger： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).showHamburger,
                "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => unref(settings).showHamburger = $event)
              }, null, 8, ["modelValue"])
            ]),
            createBaseVNode("div", _hoisted_10, [
              createTextVNode(" showLeftMenu： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).showLeftMenu,
                "onUpdate:modelValue": _cache[4] || (_cache[4] = ($event) => unref(settings).showLeftMenu = $event)
              }, null, 8, ["modelValue"])
            ]),
            createBaseVNode("div", _hoisted_11, [
              createTextVNode(" showTagsView： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).showTagsView,
                "onUpdate:modelValue": _cache[5] || (_cache[5] = ($event) => unref(settings).showTagsView = $event)
              }, null, 8, ["modelValue"])
            ]),
            createBaseVNode("div", _hoisted_12, [
              createTextVNode(" showTopNavbar： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).showTopNavbar,
                "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => unref(settings).showTopNavbar = $event)
              }, null, 8, ["modelValue"])
            ])
          ]),
          createBaseVNode("div", _hoisted_13, [
            _hoisted_14,
            _hoisted_15,
            createBaseVNode("div", _hoisted_16, [
              createTextVNode(" isNeedNprogress： "),
              createVNode(_component_el_switch, {
                modelValue: unref(settings).isNeedNprogress,
                "onUpdate:modelValue": _cache[7] || (_cache[7] = ($event) => unref(settings).isNeedNprogress = $event)
              }, null, 8, ["modelValue"])
            ])
          ])
        ])
      ]);
    };
  }
});
export {
  _sfc_main as default
};
