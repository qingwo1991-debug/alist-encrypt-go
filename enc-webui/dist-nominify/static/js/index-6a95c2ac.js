import { d as defineComponent, g as ref, e as useBasicStore, F as useConfigStore, u as useRoute, r as reactive, B as computed, L as onMounted, M as getAlistConfigReq, N as getSchemeConfigReq, O as onUnmounted, h as resolveComponent, G as resolveDirective, i as openBlock, j as createElementBlock, H as withDirectives, b as createTextVNode, c as createVNode, k as withCtx, P as normalizeStyle, t as toDisplayString, Q as Fragment, R as createCommentVNode, n as createBlock, l as createBaseVNode, S as renderList, m as unref, E as isRef, T as delete_default, U as encodeFoldNameReq, V as decodeFoldNameReq, W as saveAlistConfigReq, I as ElMessage, X as saveSchemeConfigReq, Y as getProxyDomainDictionaryReq, Z as refreshProxyDomainDictionaryReq, $ as getProxyRoutingConfigReq, a0 as saveProxyRoutingConfigReq, a1 as validateScanConfigReq, a2 as getStatsReq } from "./index-1a909033.js";
import "./lodash-d8a6c58b.js";
const _hoisted_1 = { class: "scroll-y" };
const _hoisted_2 = /* @__PURE__ */ createBaseVNode("h3", null, "Alist服务配置", -1);
const _hoisted_3 = { class: "mt-30px font-bold mb-10px" };
const _hoisted_4 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "alist的ip或者域名地址", -1);
const _hoisted_5 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "默认http", -1);
const _hoisted_6 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "代理连接后端Alist时启用h2c（需要Alist也开启enable_h2c）", -1);
const _hoisted_7 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "客户端连接代理时启用h2c（播放器/浏览器需支持）", -1);
const _hoisted_8 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "缓存文件大小映射，减少探测请求", -1);
const _hoisted_9 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "分钟", -1);
const _hoisted_10 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "记录不支持Range的上游并降级", -1);
const _hoisted_11 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "连续失败次数（1-10）", -1);
const _hoisted_12 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "连续成功次数（1-20）", -1);
const _hoisted_13 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "分钟（1-1440）", -1);
const _hoisted_14 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "秒（2-60）", -1);
const _hoisted_15 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "大文件分片并行解密", -1);
const _hoisted_16 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "用于启动扫描、后台探测和 WebDAV 预热", -1);
const _hoisted_17 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "填写后优先于扫描账号密码", -1);
const _hoisted_18 = { style: { "font-size": "12px", "line-height": "1.8", "color": "#666" } };
const _hoisted_19 = {
  key: 0,
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
};
const _hoisted_20 = { style: { "font-size": "12px", "line-height": "1.8", "color": "#666" } };
const _hoisted_21 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "12px", "margin-left": "12px" }
}, "显示中文网盘名，名单外默认直连", -1);
const _hoisted_22 = /* @__PURE__ */ createBaseVNode("span", {
  color: "gray",
  style: { "font-size": "13px", "margin-left": "12px" }
}, "example: encrypt/*", -1);
const _hoisted_23 = /* @__PURE__ */ createBaseVNode("br", null, null, -1);
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "index",
  setup(__props) {
    const labelPosition = ref("right");
    const dialogFolderFormVisible = ref(false);
    const activeName = ref("encode");
    useBasicStore();
    useConfigStore();
    useRoute();
    const folderForm = reactive({
      folderName: "my video",
      encType: "aesctr",
      folderPasswd: "123456",
      // 文件夹密码
      folderNameEnc: "",
      folderEncType: "rc4",
      password: ""
      // base password
    });
    const alistConfigForm = reactive({
      name: "",
      path: "/*",
      describe: "",
      serverHost: "192.168.1.100",
      serverPort: "5244",
      https: false,
      enableH2c: false,
      proxyH2c: false,
      enableSizeMap: true,
      sizeMapTtlMinutes: 1440,
      enableRangeCompatCache: true,
      rangeFailToDowngrade: 2,
      rangeSuccessToRecover: 3,
      rangeReprobeMinutes: 30,
      rangeProbeTimeoutSeconds: 8,
      enableParallelDecrypt: false,
      parallelDecryptConcurrency: 4,
      streamBufferKb: 512,
      scanUsername: "",
      scanPassword: "",
      scanAuthHeader: "",
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
          encPath: "333"
        }
      ]
    });
    const refSearchForm = ref();
    const providerOptions = ref([]);
    const scanValidationResult = ref(null);
    const statsRefreshTimer = ref(null);
    const probeStats = reactive({
      queueLen: 0,
      queueCap: 0,
      enqueuedTotal: 0,
      droppedTotal: 0,
      cooldownSkips: 0,
      workers: 0,
      providerLimit: 0,
      warmupEnqueueCount: 0,
      updatedAt: ""
    });
    const proxyRoutingForm = reactive({
      mode: "direct",
      url: "",
      noProxy: [],
      selectedProviderIDs: [],
      selectedDomains: [],
      rules: [],
      dial_timeout_seconds: 30,
      tls_handshake_timeout_seconds: 10,
      response_header_timeout_seconds: 15
    });
    const collectSelectedDomains = () => {
      const selectedSet = new Set((proxyRoutingForm.selectedProviderIDs || []).map((item) => String(item).toLowerCase()));
      const domains = [];
      for (const provider of providerOptions.value) {
        if (!selectedSet.has(String(provider.id).toLowerCase())) {
          continue;
        }
        for (const domain of provider.domains || []) {
          domains.push(domain);
        }
      }
      return [...new Set(domains)].sort();
    };
    const selectedDomainPreview = computed(() => {
      return collectSelectedDomains().join(", ");
    });
    const addPasswd = () => {
      alistConfigForm.passwdList.push({
        id: Math.random(),
        password: "123456",
        encType: "aesctr",
        enable: true,
        encName: false,
        encSuffix: "",
        describe: "my video",
        encPath: "/aliyun/encrypt/*"
      });
    };
    const delPasswd = (index) => {
      alistConfigForm.passwdList.splice(index, 1);
    };
    const checkFoldName = (item) => {
      dialogFolderFormVisible.value = true;
      folderForm.password = item.password;
      folderForm.encType = item.encType;
    };
    const encodeFoldName = async () => {
      const res = await encodeFoldNameReq(folderForm);
      folderForm.folderNameEnc = `${folderForm.folderName}_${res.data.folderNameEnc}`;
    };
    const decodeFoldName = async () => {
      const res = await decodeFoldNameReq(folderForm);
      folderForm.folderPasswd = res.data.folderPasswd;
      folderForm.folderEncType = res.data.folderEncType;
    };
    const saveAlistConfig = async () => {
      const toInt = (v, d) => {
        const n = Number.parseInt(v, 10);
        return Number.isFinite(n) ? n : d;
      };
      const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
      alistConfigForm.rangeFailToDowngrade = clamp(toInt(alistConfigForm.rangeFailToDowngrade, 2), 1, 10);
      alistConfigForm.rangeSuccessToRecover = clamp(toInt(alistConfigForm.rangeSuccessToRecover, 3), 1, 20);
      alistConfigForm.rangeReprobeMinutes = clamp(toInt(alistConfigForm.rangeReprobeMinutes, 30), 1, 1440);
      alistConfigForm.rangeProbeTimeoutSeconds = clamp(toInt(alistConfigForm.rangeProbeTimeoutSeconds, 8), 2, 60);
      for (const passwdInfo of alistConfigForm.passwdList) {
        if (typeof passwdInfo.encPath === "string") {
          passwdInfo.encPath = passwdInfo.encPath.split(",").map((item) => item.trim()).filter((item) => item.length > 0).join(",");
        }
      }
      saveAlistConfigReq(alistConfigForm).then((res) => {
        ElMessage.success(res.msg);
      });
      try {
        const schemeRes = await getSchemeConfigReq();
        const schemeData = schemeRes.data || {};
        schemeData.enable_h2c = alistConfigForm.proxyH2c;
        await saveSchemeConfigReq(schemeData);
      } catch (err) {
        console.error("Failed to save proxy H2C setting:", err);
      }
    };
    const loadProxyDictionary = async () => {
      var _a;
      const res = await getProxyDomainDictionaryReq();
      const providers = (((_a = res == null ? void 0 : res.data) == null ? void 0 : _a.providers) || []).map((item) => ({
        ...item,
        id: String(item.id || "").toLowerCase()
      }));
      providerOptions.value = providers;
      if ((proxyRoutingForm.selectedProviderIDs || []).length === 0) {
        proxyRoutingForm.selectedProviderIDs = providers.filter((item) => item.default_selected).map((item) => item.id);
      }
    };
    const refreshProviderDictionary = async () => {
      var _a;
      const res = await refreshProxyDomainDictionaryReq();
      const providers = (((_a = res == null ? void 0 : res.data) == null ? void 0 : _a.providers) || []).map((item) => ({
        ...item,
        id: String(item.id || "").toLowerCase()
      }));
      providerOptions.value = providers;
      ElMessage.success("已刷新网盘字典");
    };
    const loadProxyRouting = async () => {
      const res = await getProxyRoutingConfigReq();
      if (res == null ? void 0 : res.data) {
        Object.assign(proxyRoutingForm, {
          ...proxyRoutingForm,
          ...res.data,
          selectedProviderIDs: (res.data.selected_provider_ids || res.data.selectedProviderIDs || []).map((item) => String(item).toLowerCase()),
          selectedDomains: res.data.selected_domains || res.data.selectedDomains || []
        });
      }
    };
    const saveProxyRouting = async () => {
      if (proxyRoutingForm.mode === "rules" && !proxyRoutingForm.url) {
        ElMessage.error("规则分流模式需要填写代理地址");
        return;
      }
      const payload = {
        ...proxyRoutingForm,
        selectedDomains: collectSelectedDomains(),
        selected_provider_ids: proxyRoutingForm.selectedProviderIDs,
        selected_domains: collectSelectedDomains()
      };
      const res = await saveProxyRoutingConfigReq(payload);
      ElMessage.success(res.msg || "保存成功");
    };
    const validateScanConfig = async () => {
      var _a, _b;
      const res = await validateScanConfigReq(alistConfigForm);
      scanValidationResult.value = res.data;
      if ((_a = res.data) == null ? void 0 : _a.ok) {
        ElMessage.success(res.data.message || "扫描账号可用");
      } else {
        ElMessage.warning(((_b = res.data) == null ? void 0 : _b.message) || "扫描账号不可用");
      }
    };
    const refreshProbeStats = async () => {
      var _a, _b;
      const res = await getStatsReq({ reqLoading: false });
      const scheduler = ((_a = res == null ? void 0 : res.data) == null ? void 0 : _a.probe_scheduler) || {};
      const stream = ((_b = res == null ? void 0 : res.data) == null ? void 0 : _b.stream) || {};
      probeStats.queueLen = scheduler.queue_len || 0;
      probeStats.queueCap = scheduler.queue_cap || 0;
      probeStats.enqueuedTotal = scheduler.enqueued_total || 0;
      probeStats.droppedTotal = scheduler.dropped_total || 0;
      probeStats.cooldownSkips = scheduler.cooldown_skips || 0;
      probeStats.workers = scheduler.workers || 0;
      probeStats.providerLimit = scheduler.provider_limit || 0;
      probeStats.warmupEnqueueCount = stream.warmup_enqueue_count || 0;
      probeStats.updatedAt = (/* @__PURE__ */ new Date()).toLocaleTimeString();
    };
    onMounted(async () => {
      const res = await getAlistConfigReq();
      for (const passwdInfo of res.data.passwdList) {
        passwdInfo.id = Math.random();
        if (Array.isArray(passwdInfo.encPath)) {
          passwdInfo.encPath = passwdInfo.encPath.join(",");
        } else if (typeof passwdInfo.encPath !== "string") {
          passwdInfo.encPath = "";
        }
      }
      Object.assign(alistConfigForm, res.data);
      try {
        const schemeRes = await getSchemeConfigReq();
        if (schemeRes.data) {
          alistConfigForm.proxyH2c = schemeRes.data.enable_h2c || false;
        }
      } catch (err) {
        console.error("Failed to load proxy H2C setting:", err);
      }
      await loadProxyDictionary();
      await loadProxyRouting();
      await refreshProbeStats();
      statsRefreshTimer.value = window.setInterval(() => {
        refreshProbeStats().catch(() => {
        });
      }, 1e4);
    });
    onUnmounted(() => {
      if (statsRefreshTimer.value) {
        window.clearInterval(statsRefreshTimer.value);
        statsRefreshTimer.value = null;
      }
    });
    return (_ctx, _cache) => {
      const _component_el_input = resolveComponent("el-input");
      const _component_el_form_item = resolveComponent("el-form-item");
      const _component_el_switch = resolveComponent("el-switch");
      const _component_el_divider = resolveComponent("el-divider");
      const _component_el_button = resolveComponent("el-button");
      const _component_el_radio = resolveComponent("el-radio");
      const _component_el_radio_group = resolveComponent("el-radio-group");
      const _component_el_option = resolveComponent("el-option");
      const _component_el_select = resolveComponent("el-select");
      const _component_el_form = resolveComponent("el-form");
      const _component_el_tab_pane = resolveComponent("el-tab-pane");
      const _component_el_tabs = resolveComponent("el-tabs");
      const _component_el_dialog = resolveComponent("el-dialog");
      const _directive_lang = resolveDirective("lang");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        _hoisted_2,
        withDirectives((openBlock(), createElementBlock("div", _hoisted_3, [
          createTextVNode("服务地址")
        ])), [
          [_directive_lang]
        ]),
        createVNode(_component_el_form, {
          ref_key: "refSearchForm",
          ref: refSearchForm,
          "label-position": labelPosition.value,
          "label-width": "75px",
          model: alistConfigForm
        }, {
          default: withCtx(() => [
            createVNode(_component_el_form_item, {
              prop: "username",
              label: "服务器"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.serverHost,
                  "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => alistConfigForm.serverHost = $event),
                  style: { "max-width": "260px" },
                  placeholder: "192.168.1.100"
                }, null, 8, ["modelValue"]),
                _hoisted_4
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "password",
              label: "端口"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.serverPort,
                  "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => alistConfigForm.serverPort = $event),
                  style: { "max-width": "260px" },
                  placeholder: "5244"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "https",
              label: "https"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_switch, {
                  modelValue: alistConfigForm.https,
                  "onUpdate:modelValue": _cache[2] || (_cache[2] = ($event) => alistConfigForm.https = $event),
                  class: "ml-2",
                  style: { "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                }, null, 8, ["modelValue"]),
                _hoisted_5
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "enableH2c",
              label: "HTTP/2"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_switch, {
                  modelValue: alistConfigForm.enableH2c,
                  "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => alistConfigForm.enableH2c = $event),
                  class: "ml-2",
                  style: { "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                }, null, 8, ["modelValue"]),
                _hoisted_6
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "proxyH2c",
              label: "代理H2C"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_switch, {
                  modelValue: alistConfigForm.proxyH2c,
                  "onUpdate:modelValue": _cache[4] || (_cache[4] = ($event) => alistConfigForm.proxyH2c = $event),
                  class: "ml-2",
                  style: { "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                }, null, 8, ["modelValue"]),
                _hoisted_7
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "enableSizeMap",
              label: "长期映射"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_switch, {
                  modelValue: alistConfigForm.enableSizeMap,
                  "onUpdate:modelValue": _cache[5] || (_cache[5] = ($event) => alistConfigForm.enableSizeMap = $event),
                  class: "ml-2",
                  style: { "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                }, null, 8, ["modelValue"]),
                _hoisted_8
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "sizeMapTtlMinutes",
              label: "映射TTL"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.sizeMapTtlMinutes,
                  "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => alistConfigForm.sizeMapTtlMinutes = $event),
                  style: { "max-width": "260px" },
                  placeholder: "1440"
                }, null, 8, ["modelValue"]),
                _hoisted_9
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "enableRangeCompatCache",
              label: "Range兼容"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_switch, {
                  modelValue: alistConfigForm.enableRangeCompatCache,
                  "onUpdate:modelValue": _cache[7] || (_cache[7] = ($event) => alistConfigForm.enableRangeCompatCache = $event),
                  class: "ml-2",
                  style: { "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                }, null, 8, ["modelValue"]),
                _hoisted_10
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "rangeFailToDowngrade",
              label: "降级阈值"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.rangeFailToDowngrade,
                  "onUpdate:modelValue": _cache[8] || (_cache[8] = ($event) => alistConfigForm.rangeFailToDowngrade = $event),
                  style: { "max-width": "260px" },
                  placeholder: "2"
                }, null, 8, ["modelValue"]),
                _hoisted_11
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "rangeSuccessToRecover",
              label: "恢复阈值"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.rangeSuccessToRecover,
                  "onUpdate:modelValue": _cache[9] || (_cache[9] = ($event) => alistConfigForm.rangeSuccessToRecover = $event),
                  style: { "max-width": "260px" },
                  placeholder: "3"
                }, null, 8, ["modelValue"]),
                _hoisted_12
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "rangeReprobeMinutes",
              label: "重探间隔"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.rangeReprobeMinutes,
                  "onUpdate:modelValue": _cache[10] || (_cache[10] = ($event) => alistConfigForm.rangeReprobeMinutes = $event),
                  style: { "max-width": "260px" },
                  placeholder: "30"
                }, null, 8, ["modelValue"]),
                _hoisted_13
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "rangeProbeTimeoutSeconds",
              label: "探测超时"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.rangeProbeTimeoutSeconds,
                  "onUpdate:modelValue": _cache[11] || (_cache[11] = ($event) => alistConfigForm.rangeProbeTimeoutSeconds = $event),
                  style: { "max-width": "260px" },
                  placeholder: "8"
                }, null, 8, ["modelValue"]),
                _hoisted_14
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "enableParallelDecrypt",
              label: "并行解密"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_switch, {
                  modelValue: alistConfigForm.enableParallelDecrypt,
                  "onUpdate:modelValue": _cache[12] || (_cache[12] = ($event) => alistConfigForm.enableParallelDecrypt = $event),
                  class: "ml-2",
                  style: { "--el-switch-on-color": "#13ce66", "--el-switch-off-color": "#ff4949" }
                }, null, 8, ["modelValue"]),
                _hoisted_15
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "parallelDecryptConcurrency",
              label: "并发数"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.parallelDecryptConcurrency,
                  "onUpdate:modelValue": _cache[13] || (_cache[13] = ($event) => alistConfigForm.parallelDecryptConcurrency = $event),
                  style: { "max-width": "260px" },
                  placeholder: "4"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "streamBufferKb",
              label: "缓冲区KB"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.streamBufferKb,
                  "onUpdate:modelValue": _cache[14] || (_cache[14] = ($event) => alistConfigForm.streamBufferKb = $event),
                  style: { "max-width": "260px" },
                  placeholder: "512"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_divider, { "content-position": "left" }, {
              default: withCtx(() => [
                createTextVNode("扫描预取配置")
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "scanUsername",
              label: "扫描账号"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.scanUsername,
                  "onUpdate:modelValue": _cache[15] || (_cache[15] = ($event) => alistConfigForm.scanUsername = $event),
                  style: { "max-width": "260px" },
                  placeholder: "scanner"
                }, null, 8, ["modelValue"]),
                _hoisted_16
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "scanPassword",
              label: "扫描密码"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.scanPassword,
                  "onUpdate:modelValue": _cache[16] || (_cache[16] = ($event) => alistConfigForm.scanPassword = $event),
                  style: { "max-width": "260px" },
                  type: "password",
                  "show-password": "",
                  placeholder: "password"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, {
              prop: "scanAuthHeader",
              label: "授权头"
            }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: alistConfigForm.scanAuthHeader,
                  "onUpdate:modelValue": _cache[17] || (_cache[17] = ($event) => alistConfigForm.scanAuthHeader = $event),
                  style: { "max-width": "520px" },
                  placeholder: "Bearer xxx 或 Basic xxxxxx"
                }, null, 8, ["modelValue"]),
                _hoisted_17
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "配置校验" }, {
              default: withCtx(() => [
                createVNode(_component_el_button, {
                  type: "primary",
                  plain: "",
                  onClick: validateScanConfig
                }, {
                  default: withCtx(() => [
                    createTextVNode("校验扫描账号")
                  ]),
                  _: 1
                }),
                scanValidationResult.value ? (openBlock(), createElementBlock("span", {
                  key: 0,
                  style: normalizeStyle({ marginLeft: "12px", color: scanValidationResult.value.ok ? "#67c23a" : "#f56c6c" })
                }, [
                  createTextVNode(toDisplayString(scanValidationResult.value.message) + " ", 1),
                  scanValidationResult.value.status_code ? (openBlock(), createElementBlock(Fragment, { key: 0 }, [
                    createTextVNode(" (HTTP " + toDisplayString(scanValidationResult.value.status_code) + ")", 1)
                  ], 64)) : createCommentVNode("", true)
                ], 4)) : createCommentVNode("", true)
              ]),
              _: 1
            }),
            scanValidationResult.value ? (openBlock(), createBlock(_component_el_form_item, {
              key: 0,
              label: "校验详情"
            }, {
              default: withCtx(() => [
                createBaseVNode("div", _hoisted_18, [
                  createBaseVNode("div", null, "目标地址: " + toDisplayString(scanValidationResult.value.target_url || "-"), 1),
                  createBaseVNode("div", null, "认证方式: " + toDisplayString(scanValidationResult.value.auth_mode || "-"), 1),
                  createBaseVNode("div", null, "响应摘要: " + toDisplayString(scanValidationResult.value.response_hint || "-"), 1)
                ])
              ]),
              _: 1
            })) : createCommentVNode("", true),
            createVNode(_component_el_form_item, { label: "后台预取" }, {
              default: withCtx(() => [
                createVNode(_component_el_button, {
                  type: "info",
                  plain: "",
                  onClick: refreshProbeStats
                }, {
                  default: withCtx(() => [
                    createTextVNode("刷新实时数据")
                  ]),
                  _: 1
                }),
                probeStats.updatedAt ? (openBlock(), createElementBlock("span", _hoisted_19, "最近刷新: " + toDisplayString(probeStats.updatedAt), 1)) : createCommentVNode("", true)
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "预取队列" }, {
              default: withCtx(() => [
                createBaseVNode("div", _hoisted_20, [
                  createBaseVNode("div", null, "队列长度: " + toDisplayString(probeStats.queueLen) + " / " + toDisplayString(probeStats.queueCap), 1),
                  createBaseVNode("div", null, "累计入队: " + toDisplayString(probeStats.enqueuedTotal) + "，累计丢弃: " + toDisplayString(probeStats.droppedTotal), 1),
                  createBaseVNode("div", null, "冷却跳过: " + toDisplayString(probeStats.cooldownSkips) + "，工作协程: " + toDisplayString(probeStats.workers) + "，单网盘并发: " + toDisplayString(probeStats.providerLimit), 1),
                  createBaseVNode("div", null, "首帧预热累计: " + toDisplayString(probeStats.warmupEnqueueCount), 1)
                ])
              ]),
              _: 1
            }),
            createVNode(_component_el_divider, { "content-position": "left" }, {
              default: withCtx(() => [
                createTextVNode("代理分流配置")
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "代理模式" }, {
              default: withCtx(() => [
                createVNode(_component_el_radio_group, {
                  modelValue: proxyRoutingForm.mode,
                  "onUpdate:modelValue": _cache[18] || (_cache[18] = ($event) => proxyRoutingForm.mode = $event),
                  size: "small"
                }, {
                  default: withCtx(() => [
                    createVNode(_component_el_radio, {
                      label: "direct",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("直连")
                      ]),
                      _: 1
                    }),
                    createVNode(_component_el_radio, {
                      label: "env",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("环境变量")
                      ]),
                      _: 1
                    }),
                    createVNode(_component_el_radio, {
                      label: "fixed",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("固定代理")
                      ]),
                      _: 1
                    }),
                    createVNode(_component_el_radio, {
                      label: "rules",
                      border: ""
                    }, {
                      default: withCtx(() => [
                        createTextVNode("规则分流")
                      ]),
                      _: 1
                    })
                  ]),
                  _: 1
                }, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "代理地址" }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: proxyRoutingForm.url,
                  "onUpdate:modelValue": _cache[19] || (_cache[19] = ($event) => proxyRoutingForm.url = $event),
                  style: { "max-width": "380px" },
                  placeholder: "http://host.docker.internal:7890"
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "网盘多选" }, {
              default: withCtx(() => [
                createVNode(_component_el_select, {
                  modelValue: proxyRoutingForm.selectedProviderIDs,
                  "onUpdate:modelValue": _cache[20] || (_cache[20] = ($event) => proxyRoutingForm.selectedProviderIDs = $event),
                  style: { "width": "680px" },
                  multiple: "",
                  "collapse-tags": "",
                  "collapse-tags-tooltip": "",
                  filterable: "",
                  clearable: "",
                  placeholder: "选择要走代理的网盘（支持多选）"
                }, {
                  default: withCtx(() => [
                    (openBlock(true), createElementBlock(Fragment, null, renderList(providerOptions.value, (provider) => {
                      return openBlock(), createBlock(_component_el_option, {
                        key: provider.id,
                        label: `${provider.provider_name_zh} (${provider.provider_name_en}) [${provider.category}]`,
                        value: provider.id
                      }, null, 8, ["label", "value"]);
                    }), 128))
                  ]),
                  _: 1
                }, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "域名预览" }, {
              default: withCtx(() => [
                createVNode(_component_el_input, {
                  modelValue: unref(selectedDomainPreview),
                  "onUpdate:modelValue": _cache[21] || (_cache[21] = ($event) => isRef(selectedDomainPreview) ? selectedDomainPreview.value = $event : null),
                  type: "textarea",
                  rows: 4,
                  readonly: "",
                  style: { "max-width": "680px" }
                }, null, 8, ["modelValue"])
              ]),
              _: 1
            }),
            createVNode(_component_el_form_item, { label: "字典操作" }, {
              default: withCtx(() => [
                createVNode(_component_el_button, {
                  type: "primary",
                  plain: "",
                  onClick: refreshProviderDictionary
                }, {
                  default: withCtx(() => [
                    createTextVNode("从 OpenList 刷新字典")
                  ]),
                  _: 1
                }),
                _hoisted_21
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
            (openBlock(true), createElementBlock(Fragment, null, renderList(alistConfigForm.passwdList, (item, index) => {
              return openBlock(), createElementBlock("div", {
                key: item.id
              }, [
                createTextVNode(" 配置 " + toDisplayString(index + 1) + " ", 1),
                createVNode(_component_el_form_item, { label: "算法" }, {
                  default: withCtx(() => [
                    createVNode(_component_el_radio_group, {
                      modelValue: item.encType,
                      "onUpdate:modelValue": ($event) => item.encType = $event,
                      style: { "margin": "0px 5px" },
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
                      style: { "margin": "0px 20px" },
                      icon: unref(delete_default),
                      circle: "",
                      onClick: ($event) => delPasswd(index)
                    }, null, 8, ["icon", "onClick"])
                  ]),
                  _: 2
                }, 1024),
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
                      placeholder: "多个目录用逗号，隔开"
                    }, null, 8, ["modelValue", "onUpdate:modelValue"]),
                    _hoisted_22
                  ]),
                  _: 2
                }, 1024),
                createVNode(_component_el_form_item, { label: "子密码:" }, {
                  default: withCtx(() => [
                    createTextVNode(" 根据文件夹的名字自动识别文件夹的秘钥 "),
                    createVNode(_component_el_button, {
                      type: "success",
                      size: "small",
                      style: { "margin-left": "10px" },
                      onClick: ($event) => checkFoldName(item)
                    }, {
                      default: withCtx(() => [
                        createTextVNode("获取")
                      ]),
                      _: 2
                    }, 1032, ["onClick"])
                  ]),
                  _: 2
                }, 1024),
                _hoisted_23
              ]);
            }), 128)),
            createVNode(_component_el_form_item, null, {
              default: withCtx(() => [
                createVNode(_component_el_button, {
                  type: "primary",
                  onClick: saveAlistConfig
                }, {
                  default: withCtx(() => [
                    createTextVNode("保存")
                  ]),
                  _: 1
                }),
                createVNode(_component_el_button, {
                  type: "warning",
                  onClick: saveProxyRouting
                }, {
                  default: withCtx(() => [
                    createTextVNode("保存代理分流")
                  ]),
                  _: 1
                })
              ]),
              _: 1
            }),
            createVNode(_component_el_dialog, {
              modelValue: dialogFolderFormVisible.value,
              "onUpdate:modelValue": _cache[27] || (_cache[27] = ($event) => dialogFolderFormVisible.value = $event),
              title: "获取文件夹密文",
              style: { "min-width": "320px" }
            }, {
              default: withCtx(() => [
                createVNode(_component_el_tabs, {
                  modelValue: activeName.value,
                  "onUpdate:modelValue": _cache[26] || (_cache[26] = ($event) => activeName.value = $event),
                  class: "demo-tabs",
                  onTabClick: _ctx.handleClick
                }, {
                  default: withCtx(() => [
                    createVNode(_component_el_tab_pane, {
                      label: "加密名字",
                      name: "encode"
                    }, {
                      default: withCtx(() => [
                        createVNode(_component_el_form, { model: folderForm }, {
                          default: withCtx(() => [
                            createVNode(_component_el_form_item, {
                              prop: "username",
                              label: "文件夹名称"
                            }, {
                              default: withCtx(() => [
                                createVNode(_component_el_input, {
                                  modelValue: folderForm.folderName,
                                  "onUpdate:modelValue": _cache[22] || (_cache[22] = ($event) => folderForm.folderName = $event),
                                  style: { "max-width": "260px" },
                                  placeholder: "folder name"
                                }, null, 8, ["modelValue"])
                              ]),
                              _: 1
                            }),
                            createVNode(_component_el_form_item, {
                              prop: "username",
                              label: "算法类型"
                            }, {
                              default: withCtx(() => [
                                createVNode(_component_el_radio_group, {
                                  modelValue: folderForm.folderEncType,
                                  "onUpdate:modelValue": _cache[23] || (_cache[23] = ($event) => folderForm.folderEncType = $event),
                                  style: { "margin": "0 15px" },
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
                            createVNode(_component_el_form_item, {
                              prop: "username",
                              label: "文件夹密码"
                            }, {
                              default: withCtx(() => [
                                createVNode(_component_el_input, {
                                  modelValue: folderForm.folderPasswd,
                                  "onUpdate:modelValue": _cache[24] || (_cache[24] = ($event) => folderForm.folderPasswd = $event),
                                  style: { "max-width": "260px" },
                                  placeholder: "123456"
                                }, null, 8, ["modelValue"])
                              ]),
                              _: 1
                            }),
                            createVNode(_component_el_form_item, {
                              prop: "username",
                              label: "加密结果"
                            }, {
                              default: withCtx(() => [
                                createTextVNode(toDisplayString(folderForm.folderNameEnc), 1)
                              ]),
                              _: 1
                            }),
                            createVNode(_component_el_button, {
                              type: "success",
                              onClick: encodeFoldName
                            }, {
                              default: withCtx(() => [
                                createTextVNode("查询")
                              ]),
                              _: 1
                            })
                          ]),
                          _: 1
                        }, 8, ["model"])
                      ]),
                      _: 1
                    }),
                    createVNode(_component_el_tab_pane, {
                      label: "解密名字",
                      name: "decode"
                    }, {
                      default: withCtx(() => [
                        createVNode(_component_el_form, { model: folderForm }, {
                          default: withCtx(() => [
                            createVNode(_component_el_form_item, {
                              prop: "username",
                              label: "文件夹名称"
                            }, {
                              default: withCtx(() => [
                                createVNode(_component_el_input, {
                                  modelValue: folderForm.folderNameEnc,
                                  "onUpdate:modelValue": _cache[25] || (_cache[25] = ($event) => folderForm.folderNameEnc = $event),
                                  style: { "max-width": "260px" },
                                  placeholder: "folder name"
                                }, null, 8, ["modelValue"])
                              ]),
                              _: 1
                            }),
                            createVNode(_component_el_form_item, {
                              prop: "username",
                              label: "算法类型"
                            }, {
                              default: withCtx(() => [
                                createTextVNode(toDisplayString(folderForm.folderEncType), 1)
                              ]),
                              _: 1
                            }),
                            createVNode(_component_el_form_item, {
                              prop: "username",
                              label: "文件夹密码"
                            }, {
                              default: withCtx(() => [
                                createTextVNode(toDisplayString(folderForm.folderPasswd), 1)
                              ]),
                              _: 1
                            }),
                            createVNode(_component_el_button, {
                              type: "success",
                              onClick: decodeFoldName
                            }, {
                              default: withCtx(() => [
                                createTextVNode("解密")
                              ]),
                              _: 1
                            })
                          ]),
                          _: 1
                        }, 8, ["model"])
                      ]),
                      _: 1
                    })
                  ]),
                  _: 1
                }, 8, ["modelValue", "onTabClick"])
              ]),
              _: 1
            }, 8, ["modelValue"])
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
