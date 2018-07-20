<template>
<div>
  <h2>Syscall Table</h2>
  <tr>
    <th>Table</th>
    <th>Index</th>
    <th>Name</th>
    <th>Address</th>
  </tr>
  <tr v-for="syscall in Syscall" :key="syscall.name">
    <td> {{ syscall.table }} </td>
    <td> {{ syscall.index }} </td>
    <td> {{ syscall.name }} </td>
    <td> {{ syscall.address }} </td>
  </tr>
</div>
</template>

<script>
import { ALL_SYSCALLS_QUERY } from '../constants/graphql.js'

export default {
  data () {
    return {
      Syscall: [],
      loading: 0
    }
  },
  apollo: {
    Syscall: {
      query: ALL_SYSCALLS_QUERY
    }
  }
}
</script>

<style>
</style>
