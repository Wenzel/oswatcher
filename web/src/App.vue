<template>
  <div class="container">
    <nav class="navbar" role="navigation" aria-label="main navigation">
      <div class="navbar-brand">
        <a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false">
          <span aria-hidden="true"></span>
          <span aria-hidden="true"></span>
          <span aria-hidden="true"></span>
        </a>
      </div>
      <div class="navbar-menu">
        <div class="navbar-start">
        </div>
      </div>
    </nav>
    <section class="hero">
      <div class="hero-body">
        <div class="container">
          <h1 class="title">
            Windows XP
          </h1>
          <h2 class="subtitle">
            Professional SP3
          </h2>
        </div>
      </div>
    <SyscallTable/>
    </section>
  </div>
</template>

<script>
import SyscallTable from './components/SyscallTable.vue'

export default {
  data () {
    return {
      loading: 0
    }
  },
  components: {
    SyscallTable
  }
}
</script>

<style>
</style>
