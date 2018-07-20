<template>
  <div>
    <h1>OSWatcher</h1>
    <SyscallTable/>
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
