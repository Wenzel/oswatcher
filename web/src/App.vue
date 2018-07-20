<template>
  <div>
    <h1>OSWatcher</h1>
    <SyscallTable v-for="table in SyscallTable" :key="table.index" :table="table"/>
  </div>
</template>

<script>
import SyscallTable from './components/SyscallTable.vue'
import { ALL_SYSCALL_TABLES_QUERY } from './constants/graphql.js'

export default {
  data () {
    return {
      SyscallTable: [],
      loading: 0
    }
  },
  components: {
    SyscallTable
  },
  apollo: {
    SyscallTable: {
      query: ALL_SYSCALL_TABLES_QUERY
    }
  }
}
</script>

<style>
</style>
