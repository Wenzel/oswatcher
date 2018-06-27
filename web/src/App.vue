<template>
  <div>
    <h1>OSWatcher</h1>
    <h2 v-if="loading">Loading...</h2>
      <ul>
        <li v-for="inode in allInodes" :key="inode.name">
          lol
        </li>
      </ul>
  </div>
</template>

<script>
import InodeItem from './components/InodeItem.vue'
import { ALL_INODES_QUERY } from './constants/graphql'

export default {
  data () {
    return {
      allInodes: [],
      loading: 0
    }
  },
  components: {
    InodeItem
  },
  apollo: {
    Inode: {
      query: ALL_INODES_QUERY
    }
  }
}
</script>

<style>
</style>
