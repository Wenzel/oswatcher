<template>
  <div class="container">
    <h1 class="title">Syscall Table</h1>
    <b-field grouped group-multiline>
      <b-select v-model="perPage" :disabled="!isPaginated">
        <option value="5">5 per page</option>
        <option value="10">10 per page</option>
        <option value="15">15 per page</option>
        <option value="20">20 per page</option>
      </b-select>
      <div class="control is-flex">
        <b-switch v-model="isPaginated">Paginated</b-switch>
      </div>
      <div class="control is-flex">
        <b-switch v-model="isPaginationSimple" :disabled="!isPaginated">Simple pagination</b-switch>
      </div>
    </b-field>
    <b-table :data="Syscall" :columns="columns"
                  :paginated="isPaginated"
                  :per-page="perPage"
                  :current-page.sync="currentPage"
                  :pagination-simple="isPaginationSimple">
    </b-table>
  </div>
</template>

<script>
import { ALL_SYSCALLS_QUERY } from '../constants/graphql.js'

export default {
  data () {
    return {
      Syscall: [],
      columns: [
        {
          field: 'table',
          label: 'Table'
        },
        {
          field: 'index',
          label: 'Index',
          numeric: true
        },
        {
          field: 'name',
          label: 'Name'
        },
        {
          field: 'address',
          label: 'Address'
        }
      ],
      loading: 0,
      isPaginated: true,
      isPaginationSimple: false,
      currentPage: 1,
      perPage: 10
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
