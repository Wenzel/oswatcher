<template>
<div>
  <h2>Syscall Table {{ table.index }}: {{ table.name }}</h2>
  <tr>
    <th>Index</th>
    <th>Name</th>
    <th>Address</th>
  </tr>
  <tr v-for="syscall in Syscall" :key="syscall.name">
    <td> {{ syscall.index }} </td>
    <td> {{ syscall.name }} </td>
    <td> {{ syscall.address }} </td>
  </tr>
</div>
</template>

<script>
import { ALL_SYSCALLS_FOR_TABLE } from '../constants/graphql.js'

export default {
  data () {
    return {
      Syscall: [],
      loading: 0
    }
  },
  props: {
    table: Object
  },
  apollo: {
    Syscall: {
      query: ALL_SYSCALLS_FOR_TABLE,
      variables: {
        table_name: 'nt'
      }
    }
  }
}
</script>

<style>
</style>
