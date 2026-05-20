import { d as defineComponent, g as ref, r as reactive, L as onMounted, h as resolveComponent, i as openBlock, j as createElementBlock, c as createVNode, k as withCtx, l as createBaseVNode, m as unref, b as createTextVNode, Q as Fragment, S as renderList, T as delete_default, n as createBlock, t as toDisplayString, a3 as updateWebdavConfigReq, a4 as saveWebdavConfigReq, a5 as ElMessageBox, a6 as delWebdavConfigReq, I as ElMessage, a7 as getWebdavConfigReq } from "./index-1a909033.js";
const _hoisted_1 = { class: "scroll-y" };
const _hoisted_2 = /* @__PURE__ */ createBaseVNode("h3", null, "Webdav服务配置", -1);
const _hoisted_3 = /* @__PURE__ */ createBaseVNode("br", null, null, -1);
const _hoisted_4 = { class: "scroll-y" };
const _hoisted_5 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "修改后重启生效", -1);
const _hoisted_6 = { class: "dialog-footer" };
const _hoisted_7 = {
  class: "card-header",
  style: { "height": "35px" }
};
const _hoisted_8 = { style: { "margin-top": "10px" } };
const _hoisted_9 = { class: "dark" };
const _hoisted_10 = /* @__PURE__ */ createBaseVNode("br", null, null, -1);
const _hoisted_11 = { style: { "clear": "both" } };
const _hoisted_12 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "新增后重启生效", -1);
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "index",
  setup(__props) {
    const dialogFormVisible = ref(false);
    const configList = reactive([]);
    const configFormTemp = reactive({});
    const configTemp = {
      name: "webdav",
      path: "/webdav/*",
      describe: "webdav服务",
      serverHost: "192.168.1.100",
      serverPort: "5244",
      https: false,
      enable: true,
      passwdList: [
        {
          id: Math.random(),
          password: "123456",
          encType: "aesctr",
          enable: false,
          encName: false,
          // encrypt file name
          encSuffix: "",
          //
          describe: "my video",
          encPath: "/aliyun/encrypt/*"
        }
      ]
    };
    Object.assign(configFormTemp, configTemp);
    ref();
    const addPasswd = () => {
      configFormTemp.passwdList.push({
        id: Math.random(),
        password: "123456",
        encType: "aesctr",
        enable: true,
        encName: false,
        encSuffix: "",
        describe: "my video",
        encPath: "/dav/encrypt/*"
      });
    };
    const delPasswd = (index) => {
      configFormTemp.passwdList.splice(index, 1);
    };
    const editConfig = (config) => {
      dialogFormVisible.value = true;
      Object.assign(configFormTemp, config);
    };
    const addConfig = () => {
      dialogFormVisible.value = true;
      Object.assign(configFormTemp, configTemp);
    };
    const updateWebdavConfig = async (config) => {
      const result = await updateWebdavConfigReq(config);
      dialogFormVisible.value = false;
      refreshConfigList(result);
      return;
    };
    const saveWebdavConfig = async () => {
      let result = null;
      if (configFormTemp.id) {
        result = await updateWebdavConfigReq(configFormTemp);
      } else {
        result = await saveWebdavConfigReq(configFormTemp);
      }
      dialogFormVisible.value = false;
      refreshConfigList(result);
      return;
    };
    const delWebdavConfig = async (id) => {
      ElMessageBox.confirm("Are you sure to delete?").then(async () => {
        const result = await delWebdavConfigReq({ id });
        refreshConfigList(result);
        dialogFormVisible.value = false;
        ElMessage(result.msg);
      });
    };
    const refreshConfigList = async (result) => {
      const res = result || await getWebdavConfigReq();
      configList.splice(0, configList.length);
      res.data.forEach((element) => {
        const passwdList = element.passwdList;
        for (const passwdInfo of passwdList) {
          passwdInfo.id = Math.random();
        }
        configList.push(element);
      });
    };
    onMounted(async () => {
      refreshConfigList();
    });
    return (_ctx, _cache) => {
      const _component_el_input = resolveComponent("el-input");
      const _component_el_form_item = resolveComponent("el-form-item");
      const _component_el_switch = resolveComponent("el-switch");
      const _component_el_button = resolveComponent("el-button");
      const _component_el_radio = resolveComponent("el-radio");
      const _component_el_radio_group = resolveComponent("el-radio-group");
      const _component_el_form = resolveComponent("el-form");
      const _component_el_dialog = resolveComponent("el-dialog");
      const _component_el_card = resolveComponent("el-card");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        _hoisted_2,
        _hoisted_3,
        createVNode(_component_el_dialog, {
          modelValue: dialogFormVisible.value,
          "onUpdate:modelValue": _cache[7] || (_cache[7] = ($event) => dialogFormVisible.value = $event),
          title: "配置信息",
          style: { "min-width": "320px" }
        }, {
          default: withCtx(() => [
            createBaseVNode("div", _hoisted_4, [
              createVNode(_component_el_form, { model: unref(configFormTemp) }, {
                default: withCtx(() => [
                  createVNode(_component_el_form_item, {
                    prop: "username",
                    label: "服务名称"
                  }, {
                    default: withCtx(() => [
                      createVNode(_component_el_input, {
                        modelValue: unref(configFormTemp).name,
                        "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => unref(configFormTemp).name = $event),
                        style: { "max-width": "260px" },
                        placeholder: "127.0.0.1"
                      }, null, 8, ["modelValue"])
                    ]),
                    _: 1
                  }),
                  createVNode(_component_el_form_item, {
                    prop: "username",
                    label: "服务器"
                  }, {
                    default: withCtx(() => [
                      createVNode(_component_el_input, {
                        modelValue: unref(configFormTemp).serverHost,
                        "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => unref(configFormTemp).serverHost = $event),
                        style: { "max-width": "260px" },
                        placeholder: "127.0.0.1"
                      }, null, 8, ["modelValue"])
                    ]),
                    _: 1
                  }),
                  createVNode(_component_el_form_item, {
                    prop: "password",
                    label: "端口"
                  }, {
                    default: withCtx(() => [
                      createVNode(_component_el_input, {
                        modelValue: unref(configFormTemp).serverPort,
                        "onUpdate:modelValue": _cache[2] || (_cache[2] = ($event) => unref(configFormTemp).serverPort = $event),
                        style: { "max-width": "260px" },
                        placeholder: "5244"
                      }, null, 8, ["modelValue"])
                    ]),
                    _: 1
                  }),
                  createVNode(_component_el_form_item, {
                    prop: "password",
                    label: "主目录"
                  }, {
                    default: withCtx(() => [
                      createVNode(_component_el_input, {
                        modelValue: unref(configFormTemp).path,
                        "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => unref(configFormTemp).path = $event),
                        style: { "max-width": "260px" },
                        placeholder: "5244"
                      }, null, 8, ["modelValue"]),
                      _hoisted_5
                    ]),
                    _: 1
                  }),
                  createVNode(_component_el_form_item, {
                    prop: "enable",
                    label: "开启"
                  }, {
                    default: withCtx(() => [
                      createVNode(_component_el_switch, {
                        modelValue: unref(configFormTemp).enable,
                        "onUpdate:modelValue": _cache[4] || (_cache[4] = ($event) => unref(configFormTemp).enable = $event),
                        class: "ml-2",
                        style: { "margin-bottom": "5px", "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                      }, null, 8, ["modelValue"])
                    ]),
                    _: 1
                  }),
                  createVNode(_component_el_form_item, { label: "密码设置" }, {
                    default: withCtx(() => [
                      createVNode(_component_el_button, {
                        type: "success",
                        onClick: addPasswd
                      }, {
                        default: withCtx(() => [
                          createTextVNode("添加")
                        ]),
                        _: 1
                      })
                    ]),
                    _: 1
                  }),
                  (openBlock(true), createElementBlock(Fragment, null, renderList(unref(configFormTemp).passwdList, (item, index) => {
                    return openBlock(), createElementBlock("div", {
                      key: item.id
                    }, [
                      createVNode(_component_el_radio_group, {
                        modelValue: item.encType,
                        "onUpdate:modelValue": ($event) => item.encType = $event,
                        style: { "margin": "0 25px" },
                        size: "small"
                      }, {
                        default: withCtx(() => [
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
                            label: "aesctr",
                            border: ""
                          }, {
                            default: withCtx(() => [
                              createTextVNode("AES-CTR(新)")
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
                        _: 2
                      }, 1032, ["modelValue", "onUpdate:modelValue"]),
                      createTextVNode(" 开启 "),
                      createVNode(_component_el_switch, {
                        modelValue: item.enable,
                        "onUpdate:modelValue": ($event) => item.enable = $event,
                        class: "ml-2",
                        style: { "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                      }, null, 8, ["modelValue", "onUpdate:modelValue"]),
                      createVNode(_component_el_button, {
                        type: "danger",
                        style: { "margin": "5px 20px" },
                        icon: unref(delete_default),
                        circle: "",
                        onClick: ($event) => delPasswd(index)
                      }, null, 8, ["icon", "onClick"]),
                      createVNode(_component_el_form_item, { label: "密码" }, {
                        default: withCtx(() => [
                          createVNode(_component_el_input, {
                            modelValue: item.password,
                            "onUpdate:modelValue": ($event) => item.password = $event,
                            style: { "max-width": "260px", "margin-right": "10px" },
                            placeholder: "12341234"
                          }, null, 8, ["modelValue", "onUpdate:modelValue"])
                        ]),
                        _: 2
                      }, 1024),
                      createVNode(_component_el_form_item, { label: "文件名" }, {
                        default: withCtx(() => [
                          createTextVNode(" 加密 "),
                          createVNode(_component_el_switch, {
                            modelValue: item.encName,
                            "onUpdate:modelValue": ($event) => item.encName = $event,
                            class: "ml-2",
                            style: { "margin-right": "10px", "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                          }, null, 8, ["modelValue", "onUpdate:modelValue"]),
                          createTextVNode(" 后缀 "),
                          createVNode(_component_el_input, {
                            modelValue: item.encSuffix,
                            "onUpdate:modelValue": ($event) => item.encSuffix = $event,
                            style: { "max-width": "150px", "margin-left": "10px" },
                            placeholder: ".bin / 默认原文件名后缀"
                          }, null, 8, ["modelValue", "onUpdate:modelValue"])
                        ]),
                        _: 2
                      }, 1024),
                      createVNode(_component_el_form_item, { label: "备注" }, {
                        default: withCtx(() => [
                          createVNode(_component_el_input, {
                            modelValue: item.describe,
                            "onUpdate:modelValue": ($event) => item.describe = $event,
                            style: { "max-width": "260px", "margin-right": "10px" },
                            placeholder: "备注描述"
                          }, null, 8, ["modelValue", "onUpdate:modelValue"])
                        ]),
                        _: 2
                      }, 1024),
                      createVNode(_component_el_form_item, { label: "路径" }, {
                        default: withCtx(() => [
                          createVNode(_component_el_input, {
                            modelValue: item.encPath,
                            "onUpdate:modelValue": ($event) => item.encPath = $event,
                            style: { "max-width": "350px", "margin-right": "10px" },
                            placeholder: "多个路径逗号，隔开"
                          }, null, 8, ["modelValue", "onUpdate:modelValue"])
                        ]),
                        _: 2
                      }, 1024)
                    ]);
                  }), 128))
                ]),
                _: 1
              }, 8, ["model"]),
              createBaseVNode("span", _hoisted_6, [
                createVNode(_component_el_button, {
                  onClick: _cache[5] || (_cache[5] = ($event) => dialogFormVisible.value = false)
                }, {
                  default: withCtx(() => [
                    createTextVNode("取消")
                  ]),
                  _: 1
                }),
                createVNode(_component_el_button, {
                  type: "primary",
                  onClick: _cache[6] || (_cache[6] = ($event) => saveWebdavConfig())
                }, {
                  default: withCtx(() => [
                    createTextVNode("保存")
                  ]),
                  _: 1
                })
              ])
            ])
          ]),
          _: 1
        }, 8, ["modelValue"]),
        createBaseVNode("div", null, [
          (openBlock(true), createElementBlock(Fragment, null, renderList(unref(configList), (config) => {
            return openBlock(), createBlock(_component_el_card, {
              key: config.id,
              style: { "width": "250px", "margin": "10px", "float": "left" },
              class: ""
            }, {
              default: withCtx(() => [
                createBaseVNode("div", _hoisted_7, [
                  createVNode(_component_el_switch, {
                    modelValue: config.enable,
                    "onUpdate:modelValue": ($event) => config.enable = $event,
                    onClick: ($event) => updateWebdavConfig(config),
                    class: "ml-2",
                    style: { "float": "right", "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                  }, null, 8, ["modelValue", "onUpdate:modelValue", "onClick"]),
                  createBaseVNode("span", _hoisted_8, toDisplayString(config.name), 1)
                ]),
                createBaseVNode("div", _hoisted_9, "服务: " + toDisplayString(config.serverHost), 1),
                createBaseVNode("div", null, "端口: " + toDisplayString(config.serverPort), 1),
                createBaseVNode("div", null, "路径: " + toDisplayString(config.path), 1),
                createBaseVNode("div", null, "描述: " + toDisplayString(config.describe), 1),
                _hoisted_10,
                createVNode(_component_el_button, {
                  type: "danger",
                  size: "small",
                  onClick: ($event) => delWebdavConfig(config.id)
                }, {
                  default: withCtx(() => [
                    createTextVNode("删除")
                  ]),
                  _: 2
                }, 1032, ["onClick"]),
                createVNode(_component_el_button, {
                  type: "primary",
                  size: "small",
                  onClick: ($event) => editConfig(config)
                }, {
                  default: withCtx(() => [
                    createTextVNode("编辑")
                  ]),
                  _: 2
                }, 1032, ["onClick"])
              ]),
              _: 2
            }, 1024);
          }), 128))
        ]),
        createBaseVNode("div", _hoisted_11, [
          createVNode(_component_el_button, {
            type: "success",
            onClick: addConfig
          }, {
            default: withCtx(() => [
              createTextVNode("添加配置")
            ]),
            _: 1
          }),
          _hoisted_12
        ])
      ]);
    };
  }
});
export {
  _sfc_main as default
};
