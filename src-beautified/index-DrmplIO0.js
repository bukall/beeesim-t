import {
  B as e,
  I as t,
  K as n,
  S as r,
  V as i,
  _ as a,
  at as o,
  c as s,
  f as c,
  g as l,
  i as u,
  lt as d,
  n as f,
  p,
  q as m,
  s as h,
  t as g,
  tt as _,
  u as v,
  x as y,
  y as b
} from "./vue-BJsy3Kia.js";
import {
  n as x
} from "./i18n-Dh6Egl1f.js";
import {
  g as S,
  h as C,
  v as w,
  y as T
} from "./compts-wD1zJWrB.js";
import {
  c as E
} from "./libs-D6duEWS3.js";
import {
  _ as D,
  l as O,
  u as k
} from "./utils-v_n99D2T.js";
var A = {
    class: `flex flex-col mb-container size-full bg-gray-100 relative z-0`
  },
  j = {
    class: `flex-auto overflow-hidden relative z-0`
  },
  M = {
    class: `flex-none w-full bg-white shadow-t relative z-10 h-14 box-content bottom-line transition-[height] duration-200`
  },
  N = {
    class: `flex items-center size-full`
  },
  P = [`aria-selected`],
  F = {
    class: `flex flex-col items-center`
  },
  I = {
    class: `text-xs`
  },
  L = [`aria-selected`],
  R = {
    class: `flex flex-col items-center`
  },
  z = {
    class: `text-xs`
  },
  B = r({
    __name: `App`,
    setup(r) {
      O();
      let s = _(D.left[0]),
        f = _(D.left[1]),
        g = u(),
        x = _(`Index`),
        E = _();

      function k(e) {
        let t = document.querySelector(`meta[name="theme-color"]`);
        t && t.setAttribute(`content`, e)
      }
      g.beforeEach((e, t) => {
        e.meta.level && t.meta.level ? e.meta.level > t.meta.level ? (s.value = D.left[0], f.value = D.left[1]) :
          (s.value = D.right[0], f.value = D.right[1]) : (s.value = D.left[0], f.value = D.left[1]), E.value = e
          .meta.isTabbar, (e.name === `Index` || e.name === `Personal`) && (x.value = e.name)
      }), g.afterEach(e => {
        k(e.meta.themeColor || `#51a2ff`), e.meta.title && (document.title = `BeeSIM | ${e.meta.title}`)
      });

      function B(e) {
        g.push({
          name: e
        })
      }
      return (r, u) => {
        let g = e(`router-view`),
          _ = C,
          D = S,
          O = w,
          k = T;
        return t(), b(c, null, [l(`div`, A, [l(`main`, j, [y(g, null, {
          default: n(({
            Component: e
          }) => [y(h, {
            "enter-from-class": o(s),
            "leave-to-class": o(f)
          }, {
            default: n(() => [(t(), a(p, null, [(t(), a(i(e), {
              class: `inset-0 absolute transition-transform duration-300 ease-in-out flex flex-col`
            }))], 1024))]),
            _: 2
          }, 1032, [`enter-from-class`, `leave-to-class`])]),
          _: 1
        })]), y(h, {
          "enter-from-class": `h-0!`,
          "enter-active-class": `overflow-hidden`,
          "leave-active-class": `overflow-hidden`,
          "leave-to-class": `h-0!`
        }, {
          default: n(() => [m(l(`footer`, M, [l(`div`, N, [l(`div`, {
            "aria-selected": o(x) === `Index`,
            class: `flex-none w-1/2 text-info aria-selected:text-primary cursor-pointer`,
            onClick: u[0] ||= e => B(`Index`)
          }, [l(`div`, F, [u[2] ||= l(`span`, {
            class: `iconify lucide--bluetooth size-6`
          }, null, -1), l(`div`, I, d(r.$t(`mall.connect-device`)), 1)])], 8, P), l(
            `div`, {
              "aria-selected": o(x) === `Personal`,
              class: `flex-none w-1/2 text-info aria-selected:text-primary cursor-pointer`,
              onClick: u[1] ||= e => B(`Personal`)
            }, [l(`div`, R, [u[3] ||= l(`span`, {
              class: `iconify lucide--user size-6`
            }, null, -1), l(`div`, z, d(r.$t(`mall.personal-center`)), 1)])], 8, L)])], 512), [
            [v, o(E)]
          ])]),
          _: 1
        }), u[4] ||= l(`div`, {
          id: `teleport`,
          class: `relative z-20`
        }, null, -1)]), y(_), y(D), y(O), y(k)], 64)
      }
    }
  }),
  V = (function() {
    let e = typeof document < `u` && document.createElement(`link`).relList;
    return e && e.supports && e.supports(`modulepreload`) ? `modulepreload` : `preload`
  })(),
  H = function(e) {
    return `/ble/` + e
  },
  U = {};
const W = function(e, t, n) {
  let r = Promise.resolve();
  if (t && t.length > 0) {
    let e = document.getElementsByTagName(`link`),
      i = document.querySelector(`meta[property=csp-nonce]`),
      a = i?.nonce || i?.getAttribute(`nonce`);

    function o(e) {
      return Promise.all(e.map(e => Promise.resolve(e).then(e => ({
        status: `fulfilled`,
        value: e
      }), e => ({
        status: `rejected`,
        reason: e
      }))))
    }
    r = o(t.map(t => {
      if (t = H(t, n), t in U) return;
      U[t] = !0;
      let r = t.endsWith(`.css`),
        i = r ? `[rel="stylesheet"]` : ``;
      if (n)
        for (let n = e.length - 1; n >= 0; n--) {
          let i = e[n];
          if (i.href === t && (!r || i.rel === `stylesheet`)) return
        } else if (document.querySelector(`link[href="${t}"]${i}`)) return;
      let o = document.createElement(`link`);
      if (o.rel = r ? `stylesheet` : V, r || (o.as = `script`), o.crossOrigin = ``, o.href = t, a && o
        .setAttribute(`nonce`, a), document.head.appendChild(o), r) return new Promise((e, n) => {
        o.addEventListener(`load`, e), o.addEventListener(`error`, () => n(Error(
          `Unable to preload CSS for ${t}`)))
      })
    }))
  }

  function i(e) {
    let t = new Event(`vite:preloadError`, {
      cancelable: !0
    });
    if (t.payload = e, window.dispatchEvent(t), !t.defaultPrevented) throw e
  }
  return r.then(t => {
    for (let e of t || []) e.status === `rejected` && i(e.reason);
    return e().catch(i)
  })
};
var G = g({
    history: f(`/ble`),
    routes: [{
      path: `/`,
      name: `Index`,
      component: () => W(() => import(`./PageIndex-yXsT60wb.js`), []),
      meta: {
        title: `首页`,
        level: 1,
        isTabbar: !0
      }
    }, {
      path: `/personal/index`,
      name: `Personal`,
      component: () => W(() => import(`./PagePersonal-C4MptZZd.js`), []),
      meta: {
        title: `个人中心`,
        level: 2,
        isTabbar: !0,
        themeColor: `#a5c9fd`
      }
    }, {
      path: `/personal/login`,
      name: `Login`,
      component: () => W(() => import(`./PageLogin-CCd8st2-.js`), []),
      meta: {
        title: `登录BeeSIM`,
        level: 3
      }
    }, {
      path: `/extension/parser/tlv`,
      name: `TLVParser`,
      component: () => W(() => import(`./PageTlvParser-CneJobWU.js`), []),
      meta: {
        title: `BER-TLV解析器`,
        level: 4
      }
    }, {
      path: `/firmware/upgrade`,
      name: `Firmware`,
      component: () => W(() => import(`./PageFirmware-C9j28W_4.js`), []),
      meta: {
        title: `固件升级`,
        level: 2
      }
    }, {
      path: `/profile/detail`,
      name: `ProfileDetail`,
      component: () => W(() => import(`./PageProfileDetail-BzA_ZV-2.js`), []),
      meta: {
        title: `配置详情`,
        level: 2
      }
    }, {
      path: `/esim/adder`,
      name: `EsimAdder`,
      component: () => W(() => import(`./PageEsimAdder-oQCeusq4.js`), []),
      meta: {
        title: `添加eSIM`,
        level: 2
      }
    }, {
      path: `/notification/manager`,
      name: `NotificationManager`,
      component: () => W(() => import(`./PageNotificationManager-CCrdLjDz.js`), []),
      meta: {
        title: `通知管理`,
        level: 2
      }
    }, {
      path: `/personal/modify-passwd`,
      name: `ModifyPassword`,
      component: () => W(() => import(`./PagePassword-B-9S-w-e.js`), []),
      meta: {
        title: `修改登录密码`,
        level: 4
      }
    }, {
      path: `/personal/language`,
      name: `Language`,
      component: () => W(() => import(`./PageLanguage-CAzUGZZa.js`), []),
      meta: {
        title: `语言设置`,
        level: 4
      }
    }, {
      path: `/common/email-vercode`,
      name: `EmailVercode`,
      component: () => W(() => import(`./PageVercode-DHWo5IrH.js`), []),
      meta: {
        title: `邮箱验证码`,
        level: 4
      }
    }, {
      path: `/ble/setting`,
      name: `PageSetting`,
      component: () => W(() => import(`./PageSetting-C-hcH-GW.js`), []),
      meta: {
        title: `蓝牙设置`,
        level: 3
      }
    }]
  }),
  K = s(B);
K.use(x), K.use(k), K.use(G), K.use(E()), K.mount(`#app`);