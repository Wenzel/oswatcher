<template>
  <div class="container">
    <h1 class="title">Process List</h1>
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
    </b-field>
    <b-table :data="Process"
                  :paginated="isPaginated"
                  :per-page="perPage"
                  :loading="isLoading">
                  <template slot-scope="props">
                    <b-table-column field="process_addr" label="_EPROCESS">
                      {{ props.row.process_addr }}
                    </b-table-column>
      <b-table-column field="name" label="Name">
        {{ props.row.name }}
      </b-table-column>
      <b-table-column field="pid" label="PID">
        {{ props.row.pid }}
      </b-table-column>
      <b-table-column field="ppid" label="Parent PID">
        {{ props.row.ppid }}
      </b-table-column>
      <b-table-column field="thread_count" label="Threads">
        {{ props.row.thread_count }}
      </b-table-column>
      <b-table-column field="handle_count" label="handles">
        {{ props.row.handle_count }}
      </b-table-column>
      <b-table-column field="wow64" label="WOW64">
        <span class="tag tag-is-success" v-if="props.row.wow64">
          Yes
        </span>
        <span class="tag tag-is-danger" v-else>
          No
        </span>
      </b-table-column>
                  </template>
    </b-table>
  </div>
</template>

<script>
import { ALL_PROCESSES_QUERY } from '@/constants/graphql.js'

export default {
  data () {
    return {
      isPaginated: true,
      perPage: 10,
      Process: [],
      columns: [
        {
          field: 'process_addr',
          label: '_EPROCESS'
        },
        {
          field: 'name',
          label: 'Name'
        },
        {
          field: 'pid',
          label: 'PID'
        },
        {
          field: 'ppid',
          label: 'Parent PID'
        },
        {
          field: 'thread_count',
          label: 'Threads'
        },
        {
          field: 'handle_count',
          label: 'Handles'
        },
        {
          field: 'wow64',
          label: 'WOW64'
        }
      ],
      loading: 0
    }
  },
  props: [
    'os'
  ],
  computed: {
    isLoading: function () {
      return Boolean(this.loading)
    }
  },
  apollo: {
    Process: {
      query: ALL_PROCESSES_QUERY,
      variables () {
        return {
          os_name: this.os.name
        }
      }
    }
  }
}
</script>

<style>
</style>
