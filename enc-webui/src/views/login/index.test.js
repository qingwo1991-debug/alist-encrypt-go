/* eslint-disable vue/one-component-per-file */
import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h, nextTick } from 'vue'
import { routeLocationKey, routerKey } from 'vue-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/store/basic', () => ({ useBasicStore: vi.fn() }))
vi.mock('@/hooks/use-element', () => ({
  elMessage: vi.fn(),
  useElement: () => ({ formRules: { isNotNull: () => [] } })
}))
vi.mock('@/api/user', () => ({ loginReq: vi.fn() }))

import { loginReq } from '@/api/user'
import { useBasicStore } from '@/store/basic'
import Login from './index.vue'

let validationResult = false
let routeQuery
let routerPush
let setToken

const FormStub = defineComponent({
  setup(_, { expose, slots }) {
    expose({ validate: (callback) => callback(validationResult) })
    return () => h('form', slots.default?.())
  }
})

const ButtonStub = defineComponent({
  props: { loading: Boolean },
  setup(props, { attrs, slots }) {
    return () => h('button', { ...attrs, 'data-loading': String(props.loading) }, slots.default?.())
  }
})

const mountLogin = () =>
  mount(Login, {
    global: {
      provide: {
        [routeLocationKey]: { query: routeQuery },
        [routerKey]: { push: routerPush }
      },
      stubs: {
        'el-form': FormStub,
        'el-form-item': { template: '<div><slot /></div>' },
        'el-input': { template: '<input />' },
        'el-button': ButtonStub,
        'svg-icon': true
      }
    }
  })

describe('login loading state', () => {
  beforeEach(() => {
    validationResult = false
    routeQuery = {}
    routerPush = vi.fn()
    setToken = vi.fn()
    loginReq.mockReset()
    useBasicStore.mockReset()
    useBasicStore.mockReturnValue({ settings: { title: 'Test' }, setToken })
  })

  it('does not enter loading state when validation fails', async () => {
    const wrapper = mountLogin()

    await wrapper.find('button').trigger('click')

    expect(loginReq).not.toHaveBeenCalled()
    expect(wrapper.find('button').attributes('data-loading')).toBe('false')
  })

  it('always leaves loading state after login rejects', async () => {
    validationResult = true
    let rejectLogin
    loginReq.mockReturnValue(
      new Promise((_, reject) => {
        rejectLogin = reject
      })
    )
    const wrapper = mountLogin()

    await wrapper.find('button').trigger('click')
    await nextTick()
    expect(wrapper.find('button').attributes('data-loading')).toBe('true')

    rejectLogin(new Error('invalid credentials'))
    await flushPromises()
    expect(wrapper.find('button').attributes('data-loading')).toBe('false')
  })

  it.each([
    ['string', 'invalid credentials', 'invalid credentials'],
    ['Error', new Error('request failed'), 'request failed'],
    ['msg object', { msg: 'account locked' }, 'account locked']
  ])('shows a useful message for a rejected %s', async (_, rejection, expected) => {
    validationResult = true
    loginReq.mockRejectedValue(rejection)
    const wrapper = mountLogin()

    await wrapper.find('button').trigger('click')
    await flushPromises()

    expect(wrapper.find('.tip-message').text()).toBe(expected)
  })

  it('returns to the requested internal route with the remaining query', async () => {
    validationResult = true
    routeQuery = { redirect: '/reports', tab: 'recent' }
    loginReq.mockResolvedValue({ data: { jwtToken: 'jwt-token' } })
    const wrapper = mountLogin()

    await wrapper.find('button').trigger('click')
    await flushPromises()

    expect(setToken).toHaveBeenCalledWith('jwt-token')
    expect(routerPush).toHaveBeenCalledWith({ path: '/reports', query: { tab: 'recent' } })
  })
})
