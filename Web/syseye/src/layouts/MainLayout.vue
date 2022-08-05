<template>
  <q-layout view="lHh Lpr lFf" style="background-color: rgb(239, 243, 246)">
    <q-header elevated height-hint="98">
      <q-toolbar class="text-primary bg-white">
        <q-toolbar-title> DuckSysEye内部测试版本v0.0.0.1 </q-toolbar-title>
        <q-btn flat round dense icon="more_vert"></q-btn>
      </q-toolbar>
    </q-header>
    <q-drawer
      show-if-above
      :mini="miniState"
      @mouseover="miniState = false"
      @mouseout="miniState = true"
      :width="200"
      :breakpoint="500"
      bordered
      class="bg-white text-primary"
    >
      <q-scroll-area class="fit">
        <q-list padding>
          <q-item
            :active="selectLabel == 'dashboard'"
            clickable
            v-ripple
            active-class="menu-active"
            @click="selectLabel = 'dashboard'"
            to="/page/dashboard"
          >
            <q-item-section avatar>
              <q-icon name="dashboard" />
            </q-item-section>
            <q-item-section> 仪表盘 </q-item-section>
          </q-item>

          <q-item
            :active="selectLabel == 'non_hanlde_report'"
            clickable
            v-ripple
            active-class="menu-active"
            @click="selectLabel = 'non_hanlde_report';routerToThreatList(0)"
          >
            <q-item-section avatar>
              <q-icon name="report" />
            </q-item-section>
            <q-item-section> 未处理威胁列表 </q-item-section>
          </q-item>
          <q-item
            :active="selectLabel == 'handle_report'"
            clickable
            v-ripple
            active-class="menu-active"
            @click="selectLabel = 'handle_report';routerToThreatList(1)"
          >
            <q-item-section avatar>
              <q-icon name="done" />
            </q-item-section>
            <q-item-section> 已处理威胁列表 </q-item-section>
          </q-item>
          <q-item
            :active="selectLabel == 'ingore_report'"
            clickable
            v-ripple
            active-class="menu-active"
            @click="selectLabel = 'ingore_report';routerToThreatList(2)"
          >
            <q-item-section avatar>
              <q-icon name="texture" />
            </q-item-section>
            <q-item-section> 已忽略威胁列表 </q-item-section>
          </q-item>
        </q-list>
      </q-scroll-area>
    </q-drawer>

    <q-page-container>
      <router-view />
    </q-page-container>
  </q-layout>
</template>

<script>
import { defineComponent } from 'vue'

export default defineComponent({
  name: 'MainLayout',
  setup () {
    return {}
  },
  data: function () {
    return {
      selectLabel: 'non_hanlde_report',
      drawer: false,
      miniState: true
    }
  },
  methods: {
    routerToThreatList (index) {
      this.$router.push({ name: 'index', params: { queryIndex: index } })
    }
  }
})
</script>

<style lang="sass">
.menu-active
  color: white
  background: #F2C037
</style>
<style type="text/css">
::-webkit-scrollbar {
  /*滚动条整体样式*/
  width: 5px;
  /*高宽分别对应横竖滚动条的尺寸*/
  height: 4px;
}

::-webkit-scrollbar-thumb {
  /*滚动条里面小方块*/
  border-radius: 15px;
  -webkit-box-shadow: inset 0 0 5px rgba(0, 0, 0, 0.2);
  background: #027be3;
}

::-webkit-scrollbar-track {
  /*滚动条里面轨道*/
  -webkit-box-shadow: inset 0 0 5px rgba(0, 0, 0, 0.2);
  border-radius: 15px;
  background: #ededed;
}
</style>
