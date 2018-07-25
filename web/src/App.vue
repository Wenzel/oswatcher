<template>
  <div class="container">
    <nav class="navbar has-shadow" role="navigation" aria-label="main navigation">
      <div class="navbar-brand">
        <a class="navbar-item" href="http://localhost:8080">
          <img src="../assets/images/logo.png" width="120" height="40">
        </a>
        <a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false">
          <span aria-hidden="true"></span>
          <span aria-hidden="true"></span>
          <span aria-hidden="true"></span>
        </a>
      </div>
      <div class="navbar-menu">
        <div class="navbar-start">
          <router-link to="/">
            <a class="navbar-item">
              Home
            </a>
          </router-link>
        </div>
      </div>
    </nav>
    <router-view></router-view>
  </div>
</template>

<script>
import { ALL_OS_QUERY } from './constants/graphql.js'

export default {
  data () {
    return {
      OS: [],
      columns: [
        {
          field: 'name',
          label: 'OS'
        }
      ],
      loading: 0
    }
  },
  components: {
  },
  apollo: {
    OS: {
      query: ALL_OS_QUERY
    }
  }
}
</script>

<style>
</style>
