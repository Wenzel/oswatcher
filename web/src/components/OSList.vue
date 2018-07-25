<template>
  <div class="container">
    <section class="hero">
      <div class="hero-body">
        <div class="container">
          <h1 class="title">
            Operating Systems
          </h1>
        </div>
      </div>
    </section>
    <b-table :data="OS" :columns="columns" :hoverable="true"
              selectable
              @select="selected">
    </b-table>
  </div>
</template>

<script>
import { ALL_OS_QUERY } from '@/constants/graphql.js'

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
  methods: {
    selected (item) {
      this.$router.push({ path: '/os/' + item._id })
    }
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
