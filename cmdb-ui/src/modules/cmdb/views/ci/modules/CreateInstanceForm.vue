<template>
  <CustomDrawer
    :title="title + CIType.alias"
    width="800"
    @close="handleClose"
    :maskClosable="false"
    :visible="visible"
    wrapClassName="create-instance-form"
    :bodyStyle="{ paddingTop: 0 }"
    :headerStyle="{ borderBottom: 'none' }"
  >
    <div class="custom-drawer-bottom-action">
      <a-button @click="handleClose">{{ $t('cancel') }}</a-button>
      <a-button type="primary" @click="createInstance">{{ $t('submit') }}</a-button>
    </div>
    <template v-if="action === 'create'">
      <template v-for="group in attributesByGroup">
        <CreateInstanceFormByGroup
          :ref="`createInstanceFormByGroup_${group.id}`"
          :key="group.id || group.name"
          :group="group"
          :attributeList="attributeList"
          @handleFocusInput="handleFocusInput"
        />
      </template>
      <template v-if="parentsType && parentsType.length">
        <a-divider style="font-size:14px;margin:14px 0;font-weight:700;">{{
          $t('cmdb.menu.citypeRelation')
        }}</a-divider>
        <a-form>
          <a-row :gutter="24" align="top" type="flex">
            <a-col :span="12" v-for="item in parentsType" :key="item.id">
              <a-form-item :label="item.alias || item.name" :colon="false">
                <a-input-group compact style="width: 100%">
                  <a-select v-model="parentsForm[item.name].attr">
                    <a-select-option
                      :title="attr.alias || attr.name"
                      v-for="attr in filterAttributes(item.attributes)"
                      :key="attr.name"
                      :value="attr.name"
                    >
                      {{ attr.alias || attr.name }}
                    </a-select-option>
                  </a-select>
                  <a-input
                    :placeholder="$t('cmdb.ci.tips1')"
                    v-model="parentsForm[item.name].value"
                    style="width: 50%"
                  />
                </a-input-group>
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </template>
    </template>
    <template v-if="action === 'update'">
      <a-form :form="form">
        <p>{{ $t('cmdb.ci.tips2') }}</p>
        <a-row :gutter="8" v-for="list in batchUpdateLists" :key="list.name">
          <a-col :span="6">
            <a-form-item>
              <el-select showSearch size="small" filterable v-model="list.name" :placeholder="$t('cmdb.ci.tips3')">
                <el-option
                  v-for="attr in attributeList"
                  :key="attr.name"
                  :value="attr.name"
                  :disabled="batchUpdateLists.findIndex((item) => item.name === attr.name) > -1"
                  :label="attr.alias || attr.name"
                >
                </el-option>
              </el-select>
            </a-form-item>
          </a-col>
          <a-col v-if="showListOperation(list.name)" :span="3">
            <a-form-item>
              <el-select size="small" filterable v-model="list.operation" :placeholder="$t('placeholder2')">
                <el-option
                  v-for="(option) in listOperationOptions"
                  :key="option.value"
                  :value="option.value"
                  :label="$t(option.label)"
                >
                </el-option>
              </el-select>
            </a-form-item>
          </a-col>
          <a-col :span="showListOperation(list.name) ? 10 : 13">
            <a-form-item>
              <CIReferenceAttr
                v-if="getAttr(list.name).is_reference"
                :referenceTypeId="getAttr(list.name).reference_type_id"
                :isList="getAttr(list.name).is_list"
                v-decorator="[
                  list.name,
                  {
                    initialValue: getAttr(list.name).is_list ? [] : ''
                  }
                ]"
              />
              <a-switch
                v-else-if="getAttr(list.name).is_bool"
                v-decorator="[
                  list.name,
                  {
                    valuePropName: 'checked',
                    initialValue: false
                  }
                ]"
              />
              <a-select
                :style="{ width: '100%' }"
                v-decorator="[list.name, { rules: getDecoratorRules(list) }]"
                :placeholder="$t('placeholder2')"
                v-else-if="getFieldType(list.name).split('%%')[0] === 'select'"
                :mode="getFieldType(list.name).split('%%')[1] === 'multiple' ? 'multiple' : 'default'"
                showSearch
                allowClear
              >
                <a-select-option
                  :value="choice[0]"
                  :key="'New_' + choice + choice_idx"
                  v-for="(choice, choice_idx) in getSelectFieldOptions(list.name)"
                >
                  <span :style="choice[1] ? choice[1].style || {} : {}">
                    <ops-icon
                      :style="{ color: choice[1].icon.color }"
                      v-if="choice[1] && choice[1].icon && choice[1].icon.name"
                      :type="choice[1].icon.name"
                    />
                    <a-tooltip placement="topLeft" :title="choice[1] ? choice[1].label || choice[0] : choice[0]" >
                      {{ choice[1] ? choice[1].label || choice[0] : choice[0] }}
                    </a-tooltip>
                  </span>
                </a-select-option>
              </a-select>
              <a-input-number
                v-decorator="[list.name, { rules: getDecoratorRules(list) }]"
                style="width: 100%"
                v-else-if="getFieldType(list.name) === 'input_number'"
              />
              <a-date-picker
                v-decorator="[list.name, { rules: getDecoratorRules(list) }]"
                style="width: 100%"
                :format="getFieldType(list.name) == '4' ? 'YYYY-MM-DD' : 'YYYY-MM-DD HH:mm:ss'"
                :valueFormat="getFieldType(list.name) == '4' ? 'YYYY-MM-DD' : 'YYYY-MM-DD HH:mm:ss'"
                v-else-if="getFieldType(list.name) === '4' || getFieldType(list.name) === '3'"
                :showTime="getFieldType(list.name) === '4' ? false : { format: 'HH:mm:ss' }"
              />
              <a-input
                v-else-if="getFieldType(list.name) === 'input'"
                @focus="(e) => handleFocusInput(e, list)"
                v-decorator="[list.name, { rules: getDecoratorRules(list) }]"
              />
            </a-form-item>
          </a-col>
          <a-col :span="2">
            <a-form-item>
              <a :style="{ color: 'red', marginTop: '2px' }" @click="handleDelete(list.name)">
                <a-icon type="delete" />
              </a>
            </a-form-item>
          </a-col>
        </a-row>
        <a-button type="primary" ghost icon="plus" @click="handleAdd">{{ $t('cmdb.ci.newUpdateField') }}</a-button>
      </a-form>
    </template>
    <JsonEditor ref="jsonEditor" @jsonEditorOk="jsonEditorOk" />
  </CustomDrawer>
</template>

<script>
import _ from 'lodash'
import moment from 'moment'
import { Select, Option } from 'element-ui'
import { getCIType, getCITypeGroupById } from '@/modules/cmdb/api/CIType'
import { addCI } from '@/modules/cmdb/api/ci'
import JsonEditor from '../../../components/JsonEditor/jsonEditor.vue'
import { valueTypeMap } from '../../../utils/const'
import CreateInstanceFormByGroup from './createInstanceFormByGroup.vue'
import { getCITypeParent, getCanEditByParentIdChildId } from '@/modules/cmdb/api/CITypeRelation'
import CIReferenceAttr from '@/components/ciReferenceAttr/index.vue'

export default {
  name: 'CreateInstanceForm',
  components: {
    ElSelect: Select,
    ElOption: Option,
    JsonEditor,
    CreateInstanceFormByGroup,
    CIReferenceAttr
  },
  props: {
    typeIdFromRelation: {
      type: Number,
      default: 0,
    },
  },
  data() {
    return {
      action: '',
      form: this.$form.createForm(this),
      visible: false,
      attributeList: [],

      CIType: {},

      batchUpdateLists: [],
      editAttr: null,
      attributesByGroup: [],
      parentsType: [],
      parentsForm: {},
      canEdit: {},
      listOperationOptions: [
        {
          value: 'cover',
          label: 'cmdb.ci.cover'
        },
        {
          value: 'add',
          label: 'add'
        },
        {
          value: 'delete',
          label: 'delete'
        }
      ]
    }
  },
  computed: {
    title() {
      return this.action === 'create' ? this.$t('create') + ' ' : this.$t('cmdb.ci.batchUpdate') + ' '
    },
    typeId() {
      if (this.typeIdFromRelation) {
        return this.typeIdFromRelation
      }
      return this.$router.currentRoute.meta.typeId
    },
    valueTypeMap() {
      return valueTypeMap()
    },
  },
  provide() {
    return {
      getFieldType: this.getFieldType,
    }
  },
  inject: ['attrList'],
  methods: {
    moment,
    async getCIType() {
      await getCIType(this.typeId).then((res) => {
        this.CIType = res.ci_types[0]
      })
    },
    async getAttributeList() {
      const _attrList = this.attrList()
      this.attributeList = _attrList.sort((x, y) => y.is_required - x.is_required)
      await getCITypeGroupById(this.typeId).then((res1) => {
        const _attributesByGroup = res1.map((g) => {
          g.attributes = g.attributes.filter((attr) => !attr.is_computed && !attr.sys_computed)
          return g
        })
        const attrHasGroupIds = []
        res1.forEach((g) => {
          const id = g.attributes.map((attr) => attr.id)
          attrHasGroupIds.push(...id)
        })
        const otherGroupAttr = this.attributeList.filter(
          (attr) => !attrHasGroupIds.includes(attr.id) && !attr.is_computed && !attr.sys_computed
        )
        if (otherGroupAttr.length) {
          _attributesByGroup.push({ id: -1, name: this.$t('other'), attributes: otherGroupAttr })
        }
        console.log(otherGroupAttr, _attributesByGroup)
        this.attributesByGroup = _attributesByGroup
      })
    },
    createInstance() {
      const _this = this
      if (_this.action === 'update') {
        this.form.validateFields({ force: true }, (err, values) => {
          if (err) {
            return
          }
          Object.keys(values).forEach((k) => {
            const _tempFind = this.attributeList.find((item) => item.name === k)

            if (_tempFind.is_reference) {
              values[k] = values[k] ? values[k] : null
            }

            if (
              _tempFind.value_type === '3' &&
              values[k] &&
              Object.prototype.toString.call(values[k]) === '[object Object]'
            ) {
              values[k] = values[k].format('YYYY-MM-DD HH:mm:ss')
            }
            if (
              _tempFind.value_type === '4' &&
              values[k] &&
              Object.prototype.toString.call(values[k]) === '[object Object]'
            ) {
              values[k] = values[k].format('YYYY-MM-DD')
            }
            if (_tempFind.value_type === '6') {
              values[k] = values[k] ? JSON.parse(values[k]) : undefined
            }

            if (_tempFind.is_list) {
              const operation = this.batchUpdateLists?.find((item) => item.name === k)?.operation || 'cover'
              switch (operation) {
                case 'add':
                case 'delete':
                  values[k] = {
                    op: operation,
                    v: values[k]
                  }
                  break
                default:
                  break
              }
            }
          })

          _this.$emit('submit', values)
        })
      } else {
        let values = {}
        for (let i = 0; i < this.attributesByGroup.length; i++) {
          const data = this.$refs[`createInstanceFormByGroup_${this.attributesByGroup[i].id}`][0].getData()
          if (data === 'error') {
            return
          }
          values = { ...values, ...data }
        }

        Object.keys(values).forEach((k) => {
          const _tempFind = this.attributeList.find((item) => item.name === k)

          if (_tempFind.is_reference) {
            values[k] = values[k] ? values[k] : null
          }

          if (
            _tempFind.value_type === '3' &&
            values[k] &&
            Object.prototype.toString.call(values[k]) === '[object Object]'
          ) {
            values[k] = values[k].format('YYYY-MM-DD HH:mm:ss')
          }
          if (
            _tempFind.value_type === '4' &&
            values[k] &&
            Object.prototype.toString.call(values[k]) === '[object Object]'
          ) {
            values[k] = values[k].format('YYYY-MM-DD')
          }
          if (_tempFind.value_type === '6') {
            values[k] = values[k] ? JSON.parse(values[k]) : undefined
          }
        })
        values.ci_type = _this.typeId
        console.log(this.parentsForm)
        Object.keys(this.parentsForm).forEach((type) => {
          if (this.parentsForm[type].value) {
            values[`$${type}.${this.parentsForm[type].attr}`] = this.parentsForm[type].value
          }
        })
        addCI(values).then((res) => {
          _this.$message.success(this.$t('addSuccess'))
          _this.visible = false
          _this.$emit('reload', { ci_id: res.ci_id })
        })
      }

      // this.form.validateFields((err, values) => {
      //   if (err) {
      //     _this.$message.error('字段填写不符合要求！')
      //     return
      //   }
      //   Object.keys(values).forEach((k) => {
      //     if (Object.prototype.toString.call(values[k]) === '[object Object]' && values[k]) {
      //       values[k] = values[k].format('YYYY-MM-DD HH:mm:ss')
      //     }
      //     const _tempFind = this.attributeList.find((item) => item.name === k)
      //     if (_tempFind.value_type === '6') {
      //       values[k] = values[k] ? JSON.parse(values[k]) : undefined
      //     }
      //   })

      //   if (_this.action === 'update') {
      //     _this.$emit('submit', values)
      //     return
      //   }
      //   values.ci_type = _this.typeId
      //   console.log(values)
      //   this.attributesByGroup.forEach((group) => {
      //     this.$refs[`createInstanceFormByGroup_${group.id}`][0].getData()
      //   })
      //   console.log(1111)
      //   // addCI(values).then((res) => {
      //   //   _this.$message.success('新增成功!')
      //   //   _this.visible = false
      //   //   _this.$emit('reload')
      //   // })
      // })
    },
    handleClose() {
      this.visible = false
    },
    handleOpen(visible, action) {
      this.visible = visible
      this.action = action
      this.$nextTick(() => {
        this.form.resetFields()
        Promise.all([this.getCIType(), this.getAttributeList()]).then(() => {
          this.batchUpdateLists = [{
            name: this.attributeList?.[0]?.name || undefined,
            operation: 'cover'
          }]
        })
        if (action === 'create') {
          getCITypeParent(this.typeId).then(async (res) => {
            for (let i = 0; i < res.parents.length; i++) {
              await getCanEditByParentIdChildId(res.parents[i].id, this.typeId).then((p_res) => {
                this.canEdit = {
                  ..._.cloneDeep(this.canEdit),
                  [res.parents[i].id]: p_res.result,
                }
              })
            }
            this.parentsType = res.parents.filter((parent) => this.canEdit[parent.id])
            const _parentsForm = {}
            res.parents.forEach((item) => {
              const _find = item.attributes.find((attr) => attr.id === item.unique_id)
              _parentsForm[item.name] = { attr: _find.name, value: '' }
            })
            this.parentsForm = _parentsForm
          })
        }
      })
    },
    getFieldType(name) {
      const _find = this.attributeList.find((item) => item.name === name)
      if (_find) {
        if (_find.is_choice) {
          if (_find.is_list) {
            return 'select%%multiple'
          }
          return 'select'
        } else if ((_find.value_type === '0' || _find.value_type === '1') && !_find.is_list) {
          return 'input_number'
        } else if (_find.value_type === '4' || _find.value_type === '3') {
          return _find.value_type
        } else {
          return 'input'
        }
      }
      return 'input'
    },
    getAttr(name) {
      return this.attributeList.find((item) => item.name === name) ?? {}
    },
    getSelectFieldOptions(name) {
      const _find = this.attributeList.find((item) => item.name === name)
      if (_find) {
        return _find.choice_value
      }
      return []
    },
    handleAdd() {
      this.batchUpdateLists.push({
        name: undefined,
        operation: 'cover'
      })
    },
    handleDelete(name) {
      const _idx = this.batchUpdateLists.findIndex((item) => item.name === name)
      if (_idx > -1) {
        this.batchUpdateLists.splice(_idx, 1)
      }
    },
    // filterOption(input, option) {
    //   return option.componentOptions.children[0].text.toLowerCase().indexOf(input.toLowerCase()) >= 0
    // },
    handleFocusInput(e, attr) {
      console.log(attr)
      const _tempFind = this.attributeList.find((item) => item.name === attr.name)
      if (_tempFind.value_type === '6') {
        this.editAttr = attr
        e.srcElement.blur()
        const jsonData = this.form.getFieldValue(attr.name)
        this.$refs.jsonEditor.open(null, null, jsonData ? JSON.parse(jsonData) : {})
      } else {
        this.editAttr = null
      }
    },
    jsonEditorOk(jsonData) {
      this.form.setFieldsValue({ [this.editAttr.name]: JSON.stringify(jsonData) })
    },

    showListOperation(name) {
      if (!name) {
        return false
      }
      const attr = this.attributeList.find((attr) => attr.name === name)

      return attr && attr.is_list
    },

    getDecoratorRules(data) {
      const { name, operation } = data
      const isList = this.showListOperation(name)
      const rules = [
        { required: false }
      ]
      if (isList && ['delete', 'add'].includes(operation)) {
        rules[0] = {
          required: true,
          message: this.$t('placeholder1')
        }
      }

      return rules
    },
    filterAttributes(attributes) {
      return attributes.filter((attr) => {
        return !attr.is_bool && !attr.is_reference
      })
    },
  },
}
</script>
<style lang="less">
.create-instance-form {
  .ant-form-item {
    margin-bottom: 5px;
  }
  .ant-drawer-body {
    overflow-y: auto;
    height: calc(100vh - 110px);
  }
}
</style>
