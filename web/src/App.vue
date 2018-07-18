<template>
  <div>
    <h1>OSWatcher</h1>
    <PieChart :data="names"/>
    <h2 v-if="loading">Loading...</h2>
      <ul>
        <InodeItem
          v-for="inode in Inode"
          :key="inode._id"
          :inode="inode"
         >
        </InodeItem>
      </ul>
  </div>
</template>

<script>
import InodeItem from './components/InodeItem.vue'
import PieChart from './components/PieChart.vue'
import { ALL_INODES_QUERY } from './constants/graphql'

const NAMES = [
  { name: 'Sarah', value: 2502 },
  { name: 'Emma', value: 2005 },
  { name: 'Laura', value: 1968 },
  { name: 'Chloé', value: 1863 },
  { name: 'Marie', value: 1810 },
  { name: 'Emily', value: 1637 },
  { name: 'Léa', value: 1592 },
  { name: 'Camille', value: 1572 },
  { name: 'Anna', value: 1433 },
  { name: 'Manon', value: 1403 }
]

export default {
  data () {
    return {
      names: NAMES,
      Inode: [],
      loading: 0
    }
  },
  components: {
    InodeItem,
    PieChart
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
