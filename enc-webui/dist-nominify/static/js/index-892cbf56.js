import { d as defineComponent, g as ref, a as useRouter, e as useBasicStore, F as useConfigStore, r as reactive, h as resolveComponent, G as resolveDirective, i as openBlock, j as createElementBlock, H as withDirectives, b as createTextVNode, c as createVNode, k as withCtx, m as unref, I as ElMessage, J as upatePasswordReq, K as updateUsernameReq } from "./index-1a909033.js";
const _hoisted_1 = { class: "scroll-y" };
const _hoisted_2 = { class: "mt-10px mb-10px font-bold" };
const _hoisted_3 = { class: "mt-10px mb-10px font-bold" };
const _hoisted_4 = { class: "mt-30px font-bold mb-10px" };
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ defineComponent({
  ...__default__,
  __name: "index",
  setup(__props) {
    const labelPosition = ref("right");
    const router = useRouter();
    const basicStore = useBasicStore();
    const { settings, userInfo } = basicStore;
    const { setTheme, theme, setSize, size, setLanguage } = useConfigStore();
    setSize("default");
    const changeLanguage = (langParam) => {
      setLanguage(langParam);
    };
    const userForm = reactive({
      username: "",
      originalUsername: "",
      // Store original username for API call
      password: "",
      newpassword: ""
    });
    const refSearchForm = ref();
    userForm.username = userInfo.username;
    userForm.originalUsername = userInfo.username;
    const updatePasswd = () => {
      if (!userForm.password) {
        ElMessage.error("请输入原密码");
        return;
      }
      if (!userForm.newpassword) {
        ElMessage.error("请输入新密码");
        return;
      }
      upatePasswordReq({
        username: userForm.originalUsername,
        password: userForm.password,
        newpassword: userForm.newpassword
      }).then((res) => {
        ElMessage.success("密码修改成功，请重新登录");
        basicStore.setToken("");
        router.push("/login");
      }).catch((err) => {
        ElMessage.error((err == null ? void 0 : err.msg) || "修改失败");
      });
    };
    const updateUsername = () => {
      if (!userForm.password) {
        ElMessage.error("请输入密码以验证身份");
        return;
      }
      if (!userForm.username || userForm.username.length < 3) {
        ElMessage.error("用户名至少需要3个字符");
        return;
      }
      if (userForm.username === userForm.originalUsername) {
        ElMessage.warning("用户名未变更");
        return;
      }
      updateUsernameReq({
        username: userForm.originalUsername,
        password: userForm.password,
        newusername: userForm.username
      }).then((res) => {
        ElMessage.success("用户名修改成功，请重新登录");
        basicStore.setToken("");
        router.push("/login");
      }).catch((err) => {
        ElMessage.error((err == null ? void 0 : err.msg) || "修改失败");
      });
    };
    return (_ctx, _cache) => {
      const _component_el_button = resolveComponent("el-button");
      const _component_el_input = resolveComponent("el-input");
      const _component_el_form_item = resolveComponent("el-form-item");
      const _component_el_form = resolveComponent("el-form");
      const _directive_lang = resolveDirective("lang");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        withDirectives((openBlock(), createElementBlock("div", _hoisted_2, [
          createTextVNode("主题切换")
        ])), [
          [_directive_lang]
        ]),
        createVNode(_component_el_button, {
          onClick: _cache[0] || (_cache[0] = ($event) => unref(setTheme)("lighting-theme"))
        }, {
          default: withCtx(() => [
            createTextVNode("lighting-theme")
          ]),
          _: 1
        }),
        createVNode(_component_el_button, {
          onClick: _cache[1] || (_cache[1] = ($event) => unref(setTheme)("dark"))
        }, {
          default: withCtx(() => [
            createTextVNode("dark-theme")
          ]),
          _: 1
        }),
        withDirectives((openBlock(), createElementBlock("div", _hoisted_3, [
          createTextVNode("switch language")
        ])), [
          [_directive_lang]
        ]),
        createVNode(_component_el_button, {
          onClick: _cache[2] || (_cache[2] = ($event) => changeLanguage("en"))
        }, {
          default: withCtx(() => [
            createTextVNode("en")
          ]),
          _: 1
        }),
        createVNode(_component_el_button, {
          onClick: _cache[3] || (_cache[3] = ($event) => changeLanguage("zh"))
        }, {
          default: withCtx(() => [
            createTextVNode("zh")
          ]),
          _: 1
        }),
        withDirectives((openBlock(), createElementBlock("div", _hoisted_4, [
          createTextVNode("账号设置")
        ])), [
          [_directive_lang]
        ]),
        createVNode(_component_el_form, {
          ref_key: "refSearchForm",
          ref: refSearchForm,
          "label-position": labelPosition.value,
          "label-width": "80px",
          model: unref(userForm)
        }, {
          default: withCtx(() => [
            createVNode(_component_el_form_item, {
              prop: "username",
              label: "用户名"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: unref(userForm).username,
                  "onUpdate:modelValue": _cache[4] || (_cache[4] = ($event) => unref(userForm).username = $event),
                  style: { "max-width": "260px" },
                  placeholder: "username"
                }, null, 8, ["modelValue"]),
                createVNode(_component_el_button, {
                  type: "primary",
                  style: { "margin-left": "10px" },
                  onClick: updateUsername
                }, {
                  default: withCtx(() => [
                    createTextVNode("修改用户名")
                  ]),
                  _: 1
                })
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "password",
              label: "原密码"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: unref(userForm).password,
                  "onUpdate:modelValue": _cache[5] || (_cache[5] = ($event) => unref(userForm).password = $event),
                  style: { "max-width": "260px" },
                  type: "password",
                  placeholder: "password"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "newpassword",
              label: "新密码"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: unref(userForm).newpassword,
                  "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => unref(userForm).newpassword = $event),
                  style: { "max-width": "260px" },
                  type: "password",
                  placeholder: "password"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, null, {
              default: withCtx(() => [
                createVNode(_component_el_button, {
                  type: "primary",
                  onClick: updatePasswd
                }, {
                  default: withCtx(() => [
                    createTextVNode("修改密码")
                  ]),
                  _: 1
                })
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
