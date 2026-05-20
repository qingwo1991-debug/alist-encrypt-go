import { d as defineComponent, ab as storeToRefs, e as useBasicStore, h as resolveComponent, i as openBlock, j as createElementBlock, c as createVNode, k as withCtx, b as createTextVNode, l as createBaseVNode } from "./index-1a909033.js";
const _hoisted_1 = { class: "scroll-y" };
const _hoisted_2 = /* @__PURE__ */ createBaseVNode("h3", { class: "mb-20px" }, "文件转存功能（即将上线）", -1);
const _hoisted_3 = /* @__PURE__ */ createBaseVNode("div", { class: "rowSS" }, "文件转存，可以把任意的网盘文件转到加密文件夹中，建议1G内的文件使用", -1);
const _hoisted_4 = /* @__PURE__ */ createBaseVNode("div", { class: "rowSS" }, "大文件推荐使用本地加密后，再从云盘客户端上进行上传，比较可靠", -1);
const _hoisted_5 = /* @__PURE__ */ createBaseVNode("div", { class: "el-upload__tip" }, "即将上线", -1);
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "index",
  setup(__props) {
    storeToRefs(useBasicStore());
    return (_ctx, _cache) => {
      const _component_el_button = resolveComponent("el-button");
      const _component_el_upload = resolveComponent("el-upload");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        _hoisted_2,
        _hoisted_3,
        _hoisted_4,
        createVNode(_component_el_upload, {
          "file-list": _ctx.fileList,
          "onUpdate:fileList": _cache[0] || (_cache[0] = ($event) => _ctx.fileList = $event),
          class: "upload-demo",
          action: "/enc-api/encryptFile",
          multiple: "",
          "on-preview": _ctx.handlePreview,
          "on-remove": _ctx.handleRemove,
          "before-remove": _ctx.beforeRemove,
          limit: 3,
          "on-exceed": _ctx.handleExceed
        }, {
          tip: withCtx(() => [
            _hoisted_5
          ]),
          default: withCtx(() => [
            createVNode(_component_el_button, { type: "primary" }, {
              default: withCtx(() => [
                createTextVNode("Click to upload")
              ]),
              _: 1
            })
          ]),
          _: 1
        }, 8, ["file-list", "on-preview", "on-remove", "before-remove", "on-exceed"])
      ]);
    };
  }
});
export {
  _sfc_main as default
};
