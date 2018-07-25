import Vue from 'vue'
import Router from 'vue-router'
import OSList from '@/components/OSList.vue'
import OSView from '@/components/OSView.vue'

Vue.use(Router)

const routes = [
  {
    path: '/',
    component: OSList
  },
  {
    path: '/os/:id',
    component: OSView
  }
]

export default new Router({
  routes: routes
})
