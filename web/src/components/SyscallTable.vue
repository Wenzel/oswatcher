<template>
  <div class="container">
    <h1 class="title">Syscall Table</h1>
    <b-field grouped group-multiline>
      <b-select v-model="table_index" v-if="SyscallTable.length">
        <option v-for="table in SyscallTable" :key="table.index" :value="table.index">{{ table.name }}</option>
      </b-select>
      <b-select v-model="perPage" :disabled="!isPaginated">
        <option value="5">5 per page</option>
        <option value="10">10 per page</option>
        <option value="15">15 per page</option>
        <option value="20">20 per page</option>
      </b-select>
      <div class="control is-flex">
        <b-switch v-model="isPaginated">Paginated</b-switch>
      </div>
    </b-field>
    <b-table :data="Syscall" :columns="columns"
                  :paginated="isPaginated"
                  :per-page="perPage"
                  :loading="isLoading">
    </b-table>
  </div>
</template>

<script>
import { ALL_SYSCALL_TABLES_QUERY, ALL_SYSCALLS_QUERY } from '@/constants/graphql.js'

export default {
  data () {
    return {
      table_index: 0,
      SyscallTable: [],
      Syscall: [],
      columns: [
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
      perPage: 10
    }
  },
  computed: {
    isLoading: function () {
      return Boolean(this.loading)
    }
  },
  props: [
    'os'
  ],
  apollo: {
    SyscallTable: {
      query: ALL_SYSCALL_TABLES_QUERY,
      variables () {
        return {
          os_name: this.os.name
        }
      }
    },
    Syscall: {
      query: ALL_SYSCALLS_QUERY,
      variables () {
        return {
          table_index: this.table_index
        }
      },
      update (data) {
        var result = []
        for (var i = 0; i < data.Syscall.length; i++) {
          if (data.Syscall[i].ownedBy != null) {
            result.push(data.Syscall[i])
          }
        }
        return result
      }
    }
  }
}
</script>

<style>
</style>
