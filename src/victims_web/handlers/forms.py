
from flask_wtf import Form
from wtforms import fields, validators

#from victims_web.config import ALLOWED_EXTENSIONS
from victims_web.util import DEFAULT_GROUP, allowed_groups, groups


class RequiredIf(validators.Required):

    def __init__(self, other_field_name, value, negate, *args, **kwargs):
        self.other_field_name = other_field_name
        self.negate = negate
        self.value = value
        super(RequiredIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)
        if other_field is None:
            raise Exception('Invalid field "%s"' % self.other_field_name)
        test = self.value == other_field.data
        test = not test if self.negate else test
        if test:
            super(RequiredIf, self).__call__(form, field)


class GroupSelect(fields.SelectField):
    def __init__(self):
        choices = [(DEFAULT_GROUP, 'unset')]
        for group in allowed_groups():
            choices.append((group, group))
        vs = [validators.AnyOf(allowed_groups())]
        super(GroupSelect, self).__init__(
            'Group', validators=vs, choices=choices)


class ArchiveSubmit(Form):
    cves = fields.StringField('CVE(s)', validators=[
        RequiredIf('group', DEFAULT_GROUP, True)
    ])
    archive = fields.FileField('Archive', validators=[
        #validators.FileAllowed(ALLOWED_EXTENSIONS),
    ])
    group = GroupSelect()
    for (g, fs) in groups().items():
        if len(fs) > 0:
            for f in fs:
                exec('%s_%s' % (g, f) + ' = fields.HiddenField(f)')
