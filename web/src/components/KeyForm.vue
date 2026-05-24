<template>
  <v-form
    ref="form"
    lazy-validation
    v-model="formValid"
    v-if="item != null && secretStorages != null"
  >
    <v-alert :value="formError" color="error" class="mb-6">{{ formError }}</v-alert>

    <v-text-field
      v-model="item.name"
      :label="$t('keyName')"
      :rules="[(v) => !!v || $t('name_required')]"
      required
      :disabled="formSaving"
      outlined
      dense
    />

    <v-card
      class="mb-6"
      :color="$vuetify.theme.dark ? '#212121' : 'white'"
      style="background: #8585850f"
    >
      <v-tabs
          fixed-tabs
          v-model="sourceStorageTypeIndex"
      >
        <v-tab
            :disabled="formSaving || !canEditSecrets || isSynced" style="padding: 0">Local</v-tab>
        <v-tab
            :disabled="formSaving || !canEditSecrets || isSynced" style="padding: 0">Storage</v-tab>
        <v-tab :disabled="formSaving || !canEditSecrets || isSynced" style="padding: 0">Env</v-tab>
        <v-tab :disabled="formSaving || !canEditSecrets || isSynced" style="padding: 0">File</v-tab>
      </v-tabs>

      <div class="ml-4 mr-4 mt-6" v-if="sourceStorageType">
        <v-autocomplete
          v-if="supportStorages && sourceStorageType === 'vault'"
          v-model="item.source_storage_id"
          :label="$t('Storage')"
          :items="secretStorages"
          item-value="id"
          item-text="name"
          :disabled="formSaving || !canEditSecrets || isSynced"
          outlined
          dense
          clearable
        />

        <v-text-field
          v-if="supportStorages && sourceStorageType === 'vault' && item.source_storage_id != null"
          v-model="item.source_storage_key"
          :label="$t('Source Key')"
          :disabled="formSaving || !canEditSecrets || isSynced"
          outlined
          dense
        />

        <v-text-field
          v-if="supportStorages && ['env', 'file'].includes(sourceStorageType)"
          v-model="item.source_storage_key"
          :label="
            sourceStorageType === 'env' ? $t('Environment variable name') : $t('Path to the file')
          "
          :rules="[(v) => !!v || $t('type_required')]"
          :disabled="formSaving || !canEditSecrets"
          outlined
          dense
        />
      </div>
    </v-card>

    <v-select
      v-model="item.type"
      :label="$t('type')"
      :rules="[(v) => !!v || !canEditSecrets || $t('type_required')]"
      :items="inventoryTypes"
      item-value="id"
      item-text="name"
      :required="canEditSecrets"
      :disabled="formSaving || !canEditSecrets"
      outlined
      dense
    />

    <v-alert v-if="isReadOnly" type="info" text>Read-only secret storage chosen.</v-alert>

    <v-text-field
      v-model="item.login_password.login"
      :label="$t('usernameOptional')"
      v-if="!isReadOnly && item.type === 'login_password'"
      :disabled="formSaving || !canEditSecrets"
      outlined
      dense
    />

    <v-text-field
      v-model="item.login_password.password"
      :append-icon="showLoginPassword ? 'mdi-eye' : 'mdi-eye-off'"
      :label="$t('password')"
      :rules="[(v) => !!v || !canEditSecrets || $t('password_required')]"
      :class="{ 'masked-secret-input': !showLoginPassword }"
      v-if="!isReadOnly && item.type === 'login_password'"
      :required="canEditSecrets"
      :disabled="formSaving || !canEditSecrets"
      autocomplete="new-password"
      @click:append="showLoginPassword = !showLoginPassword"
      outlined
      dense
    />

    <v-text-field
      v-model="item.ssh.login"
      :label="$t('usernameOptional')"
      v-if="!isReadOnly && item.type === 'ssh'"
      :disabled="formSaving || !canEditSecrets"
      outlined
      dense
    />

    <v-text-field
      v-model="item.ssh.passphrase"
      :append-icon="showSSHPassphrase ? 'mdi-eye' : 'mdi-eye-off'"
      label="Passphrase (Optional)"
      :class="{ 'masked-secret-input': !showSSHPassphrase }"
      v-if="!isReadOnly && item.type === 'ssh'"
      :disabled="formSaving || !canEditSecrets"
      @click:append="showSSHPassphrase = !showSSHPassphrase"
      outlined
      dense
    />

    <v-textarea
      outlined
      v-model="item.ssh.private_key"
      :label="$t('privateKey')"
      :disabled="formSaving || !canEditSecrets"
      :rules="[(v) => !canEditSecrets || !!v || $t('private_key_required')]"
      v-if="!isReadOnly && item.type === 'ssh'"
    />

    <v-text-field
      v-model="item.ssh_external_agent.command"
      label="Command"
      :rules="[(v) => !canEditSecrets || !!v || 'Command is required']"
      v-if="!isReadOnly && item.type === 'ssh_agent_external'"
      :required="canEditSecrets"
      :disabled="formSaving || !canEditSecrets"
      outlined
      dense
    />

    <v-text-field
      v-model="externalAgentArgsText"
      label="Args"
      hint="Optional command-line arguments"
      persistent-hint
      v-if="!isReadOnly && item.type === 'ssh_agent_external'"
      :disabled="formSaving || !canEditSecrets"
      outlined
      dense
    />

    <v-textarea
      v-model="item.ssh_external_agent.config"
      label="Config (JSON)"
      :rules="[
        (v) => !canEditSecrets || !!v || 'Config is required',
        (v) => !canEditSecrets || isValidJson(v) || 'Config must be valid JSON',
      ]"
      v-if="!isReadOnly && item.type === 'ssh_agent_external'"
      :required="canEditSecrets"
      :disabled="formSaving || !canEditSecrets"
      outlined
      rows="6"
    />

    <v-checkbox
        v-model="item.override_secret"
        :label="$t('override')"
        v-if="!isNew"
    />

    <v-alert dense text type="info" v-if="item.type === 'none'">
      {{ $t('useThisTypeOfKeyForHttpsRepositoriesAndForPlaybook') }}
    </v-alert>
  </v-form>
</template>
<script>
import ItemFormBase from '@/components/ItemFormBase';

export default {
  mixins: [ItemFormBase],

  props: {
    supportStorages: Boolean,
  },

  data() {
    return {
      showLoginPassword: false,
      showSSHPassphrase: false,
      externalAgentArgsText: '',
      inventoryTypes: [
        {
          id: 'ssh',
          name: `${this.$t('keyFormSshKey')}`,
        },
        {
          id: 'login_password',
          name: `${this.$t('keyFormLoginPassword')}`,
        },
        {
          id: 'none',
          name: `${this.$t('keyFormNone')}`,
        },
        {
          id: 'ssh_agent_external',
          name: 'SSH External Agent',
        },
      ],
      secretStorages: null,
      isSynced: false,
    };
  },

  computed: {
    sourceStorageType() {
      return this.item?.source_storage_type;
    },

    sourceStorageTypeIndex: {
      get() {
        return (
          {
            vault: 1,
            env: 2,
            file: 3,
          }[this.item.source_storage_type] || 0
        );
      },
      set(index) {
        this.item = {
          ...this.item,
          source_storage_type: [undefined, 'vault', 'env', 'file'][index],
        };
      },
    },

    canEditSecrets() {
      return this.isNew || this.item.override_secret;
    },

    isReadOnly() {
      if (!this.sourceStorageType) {
        return false;
      }

      if (['env', 'file'].includes(this.sourceStorageType)) {
        return true;
      }

      if (this.item.source_storage_id == null) {
        return false;
      }

      const storage = this.secretStorages.find((s) => s.id === this.item.source_storage_id);
      if (storage == null) {
        return false;
      }

      return storage.readonly;
    },
  },

  async created() {
    [this.secretStorages] = await Promise.all([this.loadProjectResources('secret_storages')]);
  },

  methods: {
    afterLoadData() {
      this.isSynced = JSON.parse(this.item.plain || '{}').dvls_id != null;

      this.item.ssh = this.item.ssh || {};
      this.item.login_password = this.item.login_password || {};
      this.item.ssh_external_agent = this.item.ssh_external_agent || {
        command: '/usr/local/bin/ssh-vend-local',
        args: ['semaphore-agent', '-principal', 'ansadmin'],
        config: '{}',
      };

      if (!Array.isArray(this.item.ssh_external_agent.args)) {
        this.item.ssh_external_agent.args = ['semaphore-agent', '-principal', 'ansadmin'];
      }

      this.externalAgentArgsText = this.formatExternalAgentArgs(this.item.ssh_external_agent.args);

      if (!this.item.ssh_external_agent.command) {
        this.item.ssh_external_agent.command = '/usr/local/bin/ssh-vend-local';
      }

      if (!this.item.ssh_external_agent.config) {
        this.item.ssh_external_agent.config = '{}';
      }
    },

    isValidJson(value) {
      try {
        JSON.parse(value);
        return true;
      } catch (e) {
        return false;
      }
    },

    beforeSave() {
      this.item.ssh_external_agent.args = this.parseExternalAgentArgs(this.externalAgentArgsText);
    },

    formatExternalAgentArgs(args) {
      if (!Array.isArray(args) || args.length === 0) {
        return '';
      }

      return args.map((arg) => {
        if (arg == null) {
          return '';
        }

        const strArg = String(arg);
        if (!/[\s"']/.test(strArg)) {
          return strArg;
        }

        return `"${strArg.replace(/(["\\])/g, '\\$1')}"`;
      }).join(' ');
    },

    parseExternalAgentArgs(raw) {
      const input = (raw || '').trim();
      if (input === '') {
        return [];
      }

      const args = [];
      let current = '';
      let inSingleQuote = false;
      let inDoubleQuote = false;
      let escaped = false;

      const flush = () => {
        if (current.length > 0) {
          args.push(current);
          current = '';
        }
      };

      for (let i = 0; i < input.length; i += 1) {
        const ch = input[i];

        if (escaped) {
          current += ch;
          escaped = false;
        } else if (inSingleQuote) {
          if (ch === '\'') {
            inSingleQuote = false;
          } else {
            current += ch;
          }
        } else if (inDoubleQuote) {
          if (ch === '\\') {
            escaped = true;
          } else if (ch === '"') {
            inDoubleQuote = false;
          } else {
            current += ch;
          }
        } else if (/\s/.test(ch)) {
          flush();
        } else if (ch === '\\') {
          escaped = true;
        } else if (ch === '\'') {
          inSingleQuote = true;
        } else if (ch === '"') {
          inDoubleQuote = true;
        } else {
          current += ch;
        }
      }

      if (current.length > 0) {
        args.push(current);
      }

      return args;
    },

    getNewItem() {
      return {
        ssh: {},
        login_password: {},
        ssh_external_agent: {
          command: '/usr/local/bin/ssh-vend-local',
          args: ['semaphore-agent', '--principal', 'ansadmin'],
          config: '{}',
        },
      };
    },

    getItemsUrl() {
      return `/api/project/${this.projectId}/keys`;
    },

    getSingleItemUrl() {
      return `/api/project/${this.projectId}/keys/${this.itemId}`;
    },
  },
};
</script>
