<template>
  <div class="container">
    <section class="hero">
      <div class="hero-body">
        <div class="container">
          <h1 class="title" v-if="OS.length">
            {{ OS[0].name }}
          </h1>
        </div>
      </div>
    </section>
  </div>
</template>

<script>
import { OS_FOR_ID_QUERY } from '@/constants/graphql.js'

export default {
  data () {
    return {
      OS: [],
      os_id: parseInt(this.$route.params.id),
      loading: 0
    }
  },
  components: {
  },
  apollo: {
    OS: {
      query: OS_FOR_ID_QUERY,
      variables () {
        return {
          id: this.os_id
        }
      }
    }
  }
}
</script>

<style>
</style>
