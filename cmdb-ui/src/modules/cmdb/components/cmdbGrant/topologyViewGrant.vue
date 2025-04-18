<template>
  <div class="topology-view-grant">
    <vxe-table
      ref="xTable"
      size="mini"
      stripe
      class="ops-stripe-table"
      :data="tableData"
      :max-height="`${tableHeight}px`"
      :scroll-y="{enabled: true}"
      :row-class-name="(params) => getCurrentRowClass(params, addedRids)"
    >
      <vxe-column field="name"></vxe-column>
      <vxe-column v-for="col in columns" :key="col" :field="col" :title="permMap[col]">
        <template #default="{row}">
          <a-checkbox @change="(e) => handleChange(e, col, row)" v-model="row[col]"></a-checkbox>
        </template>
      </vxe-column>
    </vxe-table>
    <a-space>
      <span class="grant-button" @click="grantDepart">{{ $t('cmdb.components.grantUser') }}</span>
      <span class="grant-button" @click="grantRole">{{ $t('cmdb.components.grantRole') }}</span>
    </a-space>
  </div>
</template>

<script>
import { permMap } from './constants.js'
import { grantTopologyView, revokeTopologyView } from '@/modules/cmdb/api/topology.js'
import { getCurrentRowClass } from './utils'
export default {
  name: 'TopologyViewGrant',
  inject: ['loading', 'isModal'],
  props: {
    viewId: {
      type: Number,
      default: null,
    },
    resourceTypeName: {
      type: String,
      default: '',
    },
    tableData: {
      type: Array,
      default: () => [],
    },
    grantType: {
      type: String,
      default: 'relation_view',
    },
    addedRids: {
      type: Array,
      default: () => [],
    },
  },
  data() {
    return {
      columns: ['read', 'update', 'delete', 'grant'],
    }
  },
  computed: {
    windowHeight() {
      return this.$store.state.windowHeight
    },
    tableHeight() {
      if (this.isModal) {
        return (this.windowHeight - 104) / 2
      }
      return (this.windowHeight - 104) / 2 - 116
    },
    permMap() {
      return permMap()
    }
  },
  methods: {
    getCurrentRowClass,
    grantDepart() {
      this.$emit('grantDepart', this.grantType)
    },
    grantRole() {
      this.$emit('grantRole', this.grantType)
    },
    handleChange(e, col, row) {
      if (e.target.checked) {
        grantTopologyView(this.viewId, row.rid, { perms: [col], name: this.resourceTypeName }).catch(() => {
          this.$emit('getTableData')
        })
      } else {
        revokeTopologyView(this.viewId, row.rid, { perms: [col], name: this.resourceTypeName }).catch(() => {
          this.$emit('getTableData')
        })
      }
    },
  },
}
</script>

<style lang="less" scoped>
.topology-view-grant {
  padding: 10px 0;
}
</style>
