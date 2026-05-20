import { a8 as defineStore, d as defineComponent, g as ref, e as useBasicStore, F as useConfigStore, u as useRoute, r as reactive, h as resolveComponent, G as resolveDirective, i as openBlock, j as createElementBlock, H as withDirectives, b as createTextVNode, c as createVNode, k as withCtx, m as unref, n as createBlock, R as createCommentVNode, l as createBaseVNode, a9 as encryptFileReq } from "./index-1a909033.js";
import "./lodash-d8a6c58b.js";
const usePageStore = defineStore("page", {
  state: () => {
    return {
      folderInfo: { folderPath: "/test", outPath: "/test/out" }
    };
  },
  persist: {
    storage: localStorage,
    paths: ["folderInfo"]
  },
  actions: {
    setFolderInfo({ folderPath, outPath }) {
      this.$patch((state) => {
        state.folderInfo = { folderPath, outPath };
      });
    }
  }
});
const _hoisted_1 = { class: "scroll-y" };
const _hoisted_2 = /* @__PURE__ */ createBaseVNode("h3", null, "本地加解密", -1);
const _hoisted_3 = { class: "mt-30px font-bold mb-10px" };
const _hoisted_4 = { class: "" };
const _hoisted_5 = { class: "" };
const _hoisted_6 = { class: "mt-30px font-bold mb-10px" };
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "index",
  setup(__props) {
    const labelPosition = ref("right");
    ref(false);
    ref("encode");
    useBasicStore();
    const { folderInfo, setFolderInfo } = usePageStore();
    useConfigStore();
    useRoute();
    const folderForm = reactive({
      folderPath: folderInfo.folderPath,
      outPath: folderInfo.outPath,
      encType: "aesctr",
      password: "123456",
      // 文件夹密码
      operation: "enc",
      encName: false,
      encSuffix: ""
    });
    reactive({});
    const refSearchForm = ref();
    const encryptFile = () => {
      setFolderInfo(Object.assign({}, folderForm));
      encryptFileReq(folderForm).then((res) => {
        ElMessage.success(res.msg);
      });
    };
    return (_ctx, _cache) => {
      const _component_el_radio = resolveComponent("el-radio");
      const _component_el_radio_group = resolveComponent("el-radio-group");
      const _component_el_form_item = resolveComponent("el-form-item");
      const _component_el_input = resolveComponent("el-input");
      const _component_el_switch = resolveComponent("el-switch");
      const _component_el_button = resolveComponent("el-button");
      const _component_el_form = resolveComponent("el-form");
      const _directive_lang = resolveDirective("lang");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        _hoisted_2,
        withDirectives((openBlock(), createElementBlock("div", _hoisted_3, [
          createTextVNode("使用说明：")
        ])), [
          [_directive_lang]
        ]),
        withDirectives((openBlock(), createElementBlock("div", _hoisted_4, [
          createTextVNode("此本地加密的功能是把encrypt所在的系统中的文件夹进行加密，选择要加密文件夹的路径，然后点击 加密\\解密 按钮即可")
        ])), [
          [_directive_lang]
        ]),
        withDirectives((openBlock(), createElementBlock("div", _hoisted_5, [
          createTextVNode("常见使用场景是在windows打开这个encrypt.exe，启动服务后，即可针对windows中的文件夹进行加密")
        ])), [
          [_directive_lang]
        ]),
        createVNode(_component_el_form, {
          ref_key: "refSearchForm",
          ref: refSearchForm,
          "label-position": labelPosition.value,
          "label-width": "75px",
          model: unref(folderForm)
        }, {
          default: withCtx(() => [
            withDirectives((openBlock(), createElementBlock("div", _hoisted_6, [
              createTextVNode("密码设置")
            ])), [
              [_directive_lang]
            ]),
            createVNode(_component_el_form_item, { label: "操作" }, {
              default: withCtx(() => [
                createVNode(_component_el_radio_group, {
                  modelValue: unref(folderForm).operation,
                  "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => unref(folderForm).operation = $event),
                  size: "small"
                }, {
                  default: withCtx(() => [
                    createVNode(_component_el_radio, {
                      label: "enc",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("加密")
                      ]),
                      _: 1
                    }),
                    createVNode(_component_el_radio, {
                      label: "dec",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("解密")
                      ]),
                      _: 1
                    })
                  ]),
                  _: 1
                }, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "算法" }, {
              default: withCtx(() => [
                createVNode(_component_el_radio_group, {
                  modelValue: unref(folderForm).encType,
                  "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => unref(folderForm).encType = $event),
                  size: "small"
                }, {
                  default: withCtx(() => [
                    createVNode(_component_el_radio, {
                      label: "aesctr",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("AES-CTR")
                      ]),
                      _: 1
                    }),
                    createVNode(_component_el_radio, {
                      label: "rc4",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("RC4")
                      ]),
                      _: 1
                    }),
                    createVNode(_component_el_radio, {
                      label: "chacha20",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("ChaCha20")
                      ]),
                      _: 1
                    })
                  ]),
                  _: 1
                }, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "密码" }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: unref(folderForm).password,
                  "onUpdate:modelValue": _cache[2] || (_cache[2] = ($event) => unref(folderForm).password = $event),
                  style: { "max-width": "260px", "margin-right": "10px" },
                  placeholder: "12341234"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "文件名" }, {
              default: withCtx(() => [
                createTextVNode(" 加密 "),
                createVNode(_component_el_switch, {
                  modelValue: unref(folderForm).encName,
                  "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => unref(folderForm).encName = $event),
                  class: "ml-2",
                  style: { "margin-right": "10px", "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                }, null, 8, ["modelValue"]),
                createTextVNode(" 后缀 "),
                createVNode(_component_el_input, {
                  modelValue: unref(folderForm).encSuffix,
                  "onUpdate:modelValue": _cache[4] || (_cache[4] = ($event) => unref(folderForm).encSuffix = $event),
                  style: { "max-width": "150px", "margin-left": "10px" },
                  placeholder: ".bin / 默认原文件名后缀"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "文件夹" }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: unref(folderForm).folderPath,
                  "onUpdate:modelValue": _cache[5] || (_cache[5] = ($event) => unref(folderForm).folderPath = $event),
                  style: { "max-width": "260px", "margin-right": "10px" },
                  placeholder: "/home/my-video"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "输出" }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: unref(folderForm).outPath,
                  "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => unref(folderForm).outPath = $event),
                  style: { "max-width": "260px", "margin-right": "10px" },
                  placeholder: "/home/outPath"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, null, {
              default: withCtx(() => [
                unref(folderForm).operation == "enc" ? (openBlock(), createBlock(_component_el_button, {
                  key: 0,
                  type: "primary",
                  onClick: encryptFile
                }, {
                  default: withCtx(() => [
                    createTextVNode("加密")
                  ]),
                  _: 1
                })) : createCommentVNode("", true),
                unref(folderForm).operation == "dec" ? (openBlock(), createBlock(_component_el_button, {
                  key: 1,
                  type: "success",
                  onClick: encryptFile
                }, {
                  default: withCtx(() => [
                    createTextVNode("解密")
                  ]),
                  _: 1
                })) : createCommentVNode("", true)
              ]),
              _: 1
            })
          ]),
          _: 1
        }, 8, ["label-position", "model"])
      ]);
    };
  }
});
export {
  _sfc_main as default
};
